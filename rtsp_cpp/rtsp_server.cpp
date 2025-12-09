#include <gst/gst.h>
#include <gst/app/gstappsrc.h>
#include <gst/rtsp-server/rtsp-server.h>
#include <opencv2/opencv.hpp>
#include <fstream>
#include <chrono>
#include <random>

static cv::VideoCapture cap1, cap2;
static std::ofstream logFile;
static auto lastTime = std::chrono::high_resolution_clock::now();
static size_t bytesSent = 0, framesSent = 0;

static void need_data(GstElement *appsrc, guint, gpointer) {
    static std::mt19937 rng(std::random_device{}());
    static std::uniform_int_distribution<int> pick(0,1);

    cv::Mat frame;
    if (pick(rng) == 0)
        cap1 >> frame;
    else
        cap2 >> frame;

    if (frame.empty()) return;

    cv::resize(frame, frame, {640,480});

    GstBuffer *buffer = gst_buffer_new_allocate(nullptr, frame.total()*frame.elemSize(), nullptr);
    GstMapInfo map;
    gst_buffer_map(buffer, &map, GST_MAP_WRITE);
    memcpy(map.data, frame.data, map.size);
    gst_buffer_unmap(buffer, &map);

    GST_BUFFER_PTS(buffer) = gst_util_uint64_scale(framesSent, GST_SECOND, 30);
    GST_BUFFER_DURATION(buffer) = gst_util_uint64_scale(1, GST_SECOND, 30);

    bytesSent += map.size;
    framesSent++;

    auto now = std::chrono::high_resolution_clock::now();
    double dt = std::chrono::duration<double>(now - lastTime).count();

    if (dt >= 1.0) {
        double fps = framesSent / dt;
        double bitrate = (bytesSent * 8) / dt / 1e6;
        logFile << "FPS," << fps << ",Bitrate(Mbps)," << bitrate << "\n";
        lastTime = now;
        framesSent = 0;
        bytesSent = 0;
    }

    gst_app_src_push_buffer(GST_APP_SRC(appsrc), buffer);
}

int main(int argc, char** argv) {
    gst_init(&argc, &argv);

    cap1.open("video1.mp4");
    cap2.open("video2.mp4");

    logFile.open("server_metrics.csv");

    GstRTSPServer *server = gst_rtsp_server_new();
    GstRTSPMountPoints *mounts = gst_rtsp_server_get_mount_points(server);

    GstRTSPMediaFactory *factory = gst_rtsp_media_factory_new();
    gst_rtsp_media_factory_set_launch(factory,
    "( appsrc name=mysrc is-live=true block=true format=GST_FORMAT_TIME "
    "caps=video/x-raw,format=BGR,width=640,height=480,framerate=30/1 "
    "! videoconvert "
    "! x264enc tune=zerolatency speed-preset=veryfast bitrate=1500 "
    "! rtph264pay name=pay0 pt=96 )");


    g_signal_connect(factory, "media-configure", G_CALLBACK(+[](
        GstRTSPMediaFactory*, GstRTSPMedia* media, gpointer){

        GstElement *pipeline = gst_rtsp_media_get_element(media);
        GstElement *appsrc = gst_bin_get_by_name(GST_BIN(pipeline), "mysrc");

        g_object_set(G_OBJECT(appsrc),
            "stream-type", 0,
            "format", GST_FORMAT_TIME,
            "is-live", TRUE,
            "block", TRUE,
            NULL
        );

        g_signal_connect(appsrc, "need-data", G_CALLBACK(need_data), nullptr);
        gst_object_unref(appsrc);
    }), nullptr);



    gst_rtsp_mount_points_add_factory(mounts, "/test", factory);
    g_object_unref(mounts);
    gst_rtsp_server_attach(server, nullptr);

    g_print("RTSP Server running at rtsp://127.0.0.1:8554/test\n");
    GMainLoop *loop = g_main_loop_new(nullptr, FALSE);
    g_main_loop_run(loop);
}
