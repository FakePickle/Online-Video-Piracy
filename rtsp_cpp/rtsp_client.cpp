#include <fstream>
#include <chrono>
#include <opencv2/opencv.hpp>
#include <cmath>
#include <vector>


int main() {
    cv::VideoCapture cap("rtsp://192.168.3.177:8554/test");
    if (!cap.isOpened()) return -1;

    std::ofstream log("client_metrics.csv");

    auto last = std::chrono::high_resolution_clock::now();
    size_t frames = 0, bytes = 0;

    std::vector<double> arrivalTimes;

    while (true) {
        cv::Mat frame;
        auto now = std::chrono::high_resolution_clock::now();
        cap >> frame;
        if (frame.empty()) break;

        frames++;
        bytes += frame.total() * frame.elemSize();
        arrivalTimes.push_back(std::chrono::duration<double>(now.time_since_epoch()).count());

        double dt = std::chrono::duration<double>(now - last).count();
        if (dt >= 1.0) {
            double fps = frames / dt;
            double bitrate = (bytes * 8) / dt / 1e6;

            // Compute jitter
            double jitter = 0;
            if (arrivalTimes.size() > 2) {
                for (size_t i=2;i<arrivalTimes.size();i++)
                    jitter += fabs((arrivalTimes[i]-arrivalTimes[i-1]) -
                                    (arrivalTimes[i-1]-arrivalTimes[i-2]));
                jitter /= arrivalTimes.size();
            }

            log << "FPS," << fps
                << ",Bitrate(Mbps)," << bitrate
                << ",Jitter," << jitter << "\n";

            frames = 0;
            bytes = 0;
            arrivalTimes.clear();
            last = now;
        }

        cv::imshow("Client", frame);
        if (cv::waitKey(1) == 27) break;
    }
}
