// stress_rtsp_client.cpp
#include <opencv2/opencv.hpp>
#include <iostream>
#include <fstream>
#include <thread>
#include <mutex>
#include <vector>
#include <chrono>
#include <atomic>

struct ThreadResult {
    int id;
    bool ok;
};

std::mutex logMutex;

void client_worker(int id,
                   const std::string &url,
                   int durationSeconds,
                   std::ofstream &logFile,
                   std::atomic<bool> &stopFlag) {
    cv::VideoCapture cap(url);
    if (!cap.isOpened()) {
        std::lock_guard<std::mutex> lk(logMutex);
        std::cerr << "[Thread " << id << "] Failed to open " << url << "\n";
        return;
    }

    auto start = std::chrono::high_resolution_clock::now();
    auto lastLog = start;
    size_t frames = 0;
    size_t bytes = 0;
    std::vector<double> arrivals;

    while (!stopFlag.load()) {
        auto now = std::chrono::high_resolution_clock::now();
        double totalElapsed = std::chrono::duration<double>(now - start).count();
        if (totalElapsed >= durationSeconds) break;

        cv::Mat frame;
        if (!cap.read(frame) || frame.empty()) {
            // no more data or error
            break;
        }

        double t = std::chrono::duration<double>(now.time_since_epoch()).count();
        arrivals.push_back(t);
        frames++;
        bytes += frame.total() * frame.elemSize();

        double windowElapsed = std::chrono::duration<double>(now - lastLog).count();
        if (windowElapsed >= 1.0) {
            double fps = frames / windowElapsed;
            double bitrateMbps = (bytes * 8.0) / windowElapsed / 1e6;

            // jitter: average absolute difference between successive inter-arrival times
            double jitter = 0.0;
            if (arrivals.size() > 2) {
                std::vector<double> diffs;
                diffs.reserve(arrivals.size() - 1);
                for (size_t i = 1; i < arrivals.size(); ++i) {
                    diffs.push_back(arrivals[i] - arrivals[i - 1]);
                }
                double mean = 0.0;
                for (double d : diffs) mean += d;
                mean /= diffs.size();
                double sumAbs = 0.0;
                for (double d : diffs) sumAbs += std::abs(d - mean);
                jitter = sumAbs / diffs.size();
            }

            {
                std::lock_guard<std::mutex> lk(logMutex);
                logFile << "Thread," << id
                        << ",FPS," << fps
                        << ",Bitrate(Mbps)," << bitrateMbps
                        << ",Jitter," << jitter
                        << "\n";
                logFile.flush();
            }

            frames = 0;
            bytes = 0;
            arrivals.clear();
            lastLog = now;
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0]
                  << " <rtsp-url-base> <num_threads> <duration_seconds>\n"
                  << "Example: " << argv[0]
                  << " rtsp://192.168.3.177:8554/test0 16 60\n";
        return 1;
    }

    std::string baseUrl = argv[1];
    int numThreads = std::stoi(argv[2]);
    int duration = std::stoi(argv[3]);

    std::ofstream logFile("client_metrics.csv", std::ios::out);
    if (!logFile.is_open()) {
        std::cerr << "Failed to open client_metrics.csv for writing\n";
        return 1;
    }

    std::atomic<bool> stopFlag(false);
    std::vector<std::thread> workers;

    std::cout << "Starting " << numThreads << " client threads on " << baseUrl
              << " for " << duration << " seconds\n";

    for (int i = 0; i < numThreads; ++i) {
        // If you want to spread across multiple streams, change URL per thread:
        // e.g., use /test0, /test1, /test2, /test3 in round-robin:
        // std::string url = baseUrlBase + std::to_string(i % NUM_STREAMS);
        std::string url = baseUrl; // all hit same mount
        workers.emplace_back(client_worker, i, url, duration,
                             std::ref(logFile), std::ref(stopFlag));
    }

    // wait for duration and then signal stop just in case
    std::this_thread::sleep_for(std::chrono::seconds(duration));
    stopFlag.store(true);

    for (auto &t : workers) {
        if (t.joinable()) t.join();
    }

    std::cout << "Done. Metrics written to client_metrics.csv\n";
    return 0;
}
