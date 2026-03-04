#include <iostream>
#include <vector>
#include <string>
#include "anti_cheat.pb.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    // Test ClientConfig parsing
    {
        anti_cheat::ClientConfig config;
        config.ParseFromArray(data, size);
    }

    // Test TargetedSensorCommand parsing
    {
        anti_cheat::TargetedSensorCommand cmd;
        cmd.ParseFromArray(data, size);
    }

    // Test Report construction
    {
        anti_cheat::Report report;
        report.ParseFromArray(data, size);
    }

    return 0;
}

#include <google/protobuf/util/json_util.h>
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "absl/log/globals.h"

void RunSimulatedFuzz(const std::string& label, const std::vector<uint8_t>& data) {
    std::cout << "\n[Simulation] Testing: " << label << " (" << data.size() << " bytes)" << std::endl;
    LLVMFuzzerTestOneInput(data.data(), data.size());

    google::protobuf::util::JsonPrintOptions options;
    options.add_whitespace = true;
    std::string json;

    // Try to parse as Report
    anti_cheat::Report report;
    if (report.ParseFromArray(data.data(), (int)data.size())) {
        if (google::protobuf::util::MessageToJsonString(report, &json, options).ok()) {
            std::cout << "Parsed as Report:\n" << json << std::endl;
            return;
        }
    }

    // Try to parse as ClientConfig (check if any field set)
    anti_cheat::ClientConfig cfg;
    if (cfg.ParseFromArray(data.data(), (int)data.size())) {
        if (cfg.has_heavy_scan_budget_ms() || cfg.harmful_keywords_size() > 0) {
            if (google::protobuf::util::MessageToJsonString(cfg, &json, options).ok()) {
                std::cout << "Parsed as ClientConfig:\n" << json << std::endl;
                return;
            }
        }
    }

    // Try to parse as TargetedSensorCommand
    anti_cheat::TargetedSensorCommand cmd;
    if (cmd.ParseFromArray(data.data(), (int)data.size())) {
        if (!cmd.sensor_name().empty()) {
            if (google::protobuf::util::MessageToJsonString(cmd, &json, options).ok()) {
                std::cout << "Parsed as TargetedSensorCommand:\n" << json << std::endl;
                return;
            }
        }
    }

    std::cout << "[Info] Data did not match any known message type (Expected in fuzzing)." << std::endl;
}

int main(int argc, char **argv) {
    absl::InitializeLog();
    absl::SetMinLogLevel(absl::LogSeverityAtLeast::kFatal);

    std::cout << "=== AntiCheat Protobuf Fuzz (Verbose Simulation) ===" << std::endl;
    std::cout << "This target is compiled with /fsanitize=fuzzer for engine-led fuzzing." << std::endl;
    std::cout << "Running built-in smoke tests..." << std::endl;

    // Case 1: Corrupted data
    RunSimulatedFuzz("Random/Corrupted Data", {0x08, 0x96, 0x01, 0x12, 0x0A, 0xFF, 0xEE, 0xDD});

    // Case 2: Valid Evidence Report
    anti_cheat::Report report;
    report.set_session_id("fuzz-session-123");
    report.set_timestamp_ms(123456789);
    report.set_type(anti_cheat::REPORT_EVIDENCE);
    std::vector<uint8_t> valid_data(report.ByteSizeLong());
    report.SerializeToArray(valid_data.data(), (int)valid_data.size());
    RunSimulatedFuzz("Valid Report (Evidence)", valid_data);

    // Case 3: Valid Targeted Command
    anti_cheat::TargetedSensorCommand cmd;
    cmd.set_sensor_name("MemorySecuritySensor");
    cmd.set_request_id("cmd-001");
    std::vector<uint8_t> cmd_data(cmd.ByteSizeLong());
    cmd.SerializeToArray(cmd_data.data(), (int)cmd_data.size());
    RunSimulatedFuzz("Valid Targeted Command", cmd_data);

    // Case 4: ClientConfig (Partial)
    anti_cheat::ClientConfig cfg;
    cfg.set_heavy_scan_budget_ms(100);
    cfg.add_harmful_keywords("speedhack");
    std::vector<uint8_t> cfg_data(cfg.ByteSizeLong());
    cfg.SerializeToArray(cfg_data.data(), (int)cfg_data.size());
    RunSimulatedFuzz("Valid ClientConfig (Partial)", cfg_data);

    std::cout << "\n[Smoke Test Completed]" << std::endl;
    return 0;
}
