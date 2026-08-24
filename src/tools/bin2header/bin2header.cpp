// enc_dec.cpp : Utility tool to encode binary files into C++ header files.
//

#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>

#include <iostream>
#include <filesystem>
#include <fstream>
#include <format>
#include <vector>
#include <algorithm>
#include <cstring>
#include <cstdint>
#include <span>

namespace fs = std::filesystem;

struct EncodedResult {
	std::string header_content;
	std::string output_filename;
};

static EncodedResult encode_binary_to_header(const std::string& stem, const std::string& extension, std::span<const uint8_t> data) {
	std::string filename = stem;
	std::string ext = extension.starts_with('.') ? extension.substr(1) : extension;
	std::replace(filename.begin(), filename.end(), '.', '_');

	std::string upper_filename = filename;
	std::string upper_ext = ext;
	std::transform(upper_filename.begin(), upper_filename.end(), upper_filename.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
	std::transform(upper_ext.begin(), upper_ext.end(), upper_ext.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });

	const size_t data_size = data.size();
	const size_t slot_count = data_size / 4;
	const size_t remainder = data_size % 4;
	const size_t total_slots = slot_count + (remainder ? 1 : 0);

	std::string result = "#pragma once\n\n";
	result += std::format("inline constexpr unsigned int {}_{}_SIZE = {};\n\n", upper_filename, upper_ext, data_size);
	result += std::format("inline constexpr unsigned int {}_{}_DATA[{}] = {{", upper_filename, upper_ext, total_slots);

	for (size_t i = 0; i < slot_count; i += 4) {
		result += "\n\t";
		const size_t chunk = std::min<size_t>(slot_count - i, 4);
		for (size_t l = 0; l < chunk; l++) {
			uint32_t val = 0;
			std::memcpy(&val, &data[(i + l) * 4], sizeof(val));
			result += std::format("0x{:08x}, ", val ^ 0xFFFFFFFF);
		}
	}

	if (remainder != 0) {
		if (slot_count % 4 == 0) {
			result += "\n\t";
		}
		uint32_t val = 0;
		for (size_t i = 0; i < remainder; i++) {
			val |= static_cast<uint32_t>(data[data_size - remainder + i]) << (i * 8);
		}
		result += std::format("0x{:08x}", val ^ 0xFFFFFFFF);
	}

	result += "\n};\n";

	return {
		.header_content = std::move(result),
		.output_filename = ext.empty() ? std::format("{}_bin.h", filename) : std::format("{}_{}_bin.h", filename, ext)
	};
}

static bool process_file(const fs::path& input_path, const fs::path& explicit_output_path = "") {
	std::ifstream f(input_path, std::ios::binary | std::ios::ate);
	if (!f.is_open()) {
		std::cerr << std::format("[-] Failed to open: {}\n", input_path.string());
		return false;
	}

	const auto file_size = f.tellg();
	if (file_size <= 0) {
		std::cerr << std::format("[-] Invalid or empty file: {}\n", input_path.string());
		return false;
	}

	std::vector<uint8_t> data(static_cast<size_t>(file_size));
	f.seekg(0, std::ios::beg);
	f.read(reinterpret_cast<char*>(data.data()), data.size());
	f.close();

	const auto encoded = encode_binary_to_header(input_path.stem().string(), input_path.extension().string(), data);

	fs::path out_path;
	if (explicit_output_path.empty()) {
		out_path = input_path.parent_path() / encoded.output_filename;
	} else if (fs::is_directory(explicit_output_path)) {
		out_path = explicit_output_path / encoded.output_filename;
	} else {
		out_path = explicit_output_path;
	}

	if (out_path.has_parent_path()) {
		fs::create_directories(out_path.parent_path());
	}

	std::ofstream out(out_path, std::ios::trunc);
	if (out.is_open()) {
		out << encoded.header_content;
		out.close();
		std::cout << std::format("[+] Generated: {}\n", out_path.string());
		return true;
	}

	std::cerr << std::format("[-] Failed to write output: {}\n", out_path.string());
	return false;
}

TEST_CASE("encode_binary_to_header: 4-byte aligned payload") {
	const std::vector<uint8_t> input = { 0x01, 0x02, 0x03, 0x04 };
	auto res = encode_binary_to_header("test", ".sys", input);

	CHECK(res.output_filename == "test_sys_bin.h");
	CHECK(res.header_content.find("inline constexpr unsigned int TEST_SYS_SIZE = 4;") != std::string::npos);
	CHECK(res.header_content.find("inline constexpr unsigned int TEST_SYS_DATA[1] = {") != std::string::npos);
	CHECK(res.header_content.find("0xfbfcfdfe") != std::string::npos);
}

TEST_CASE("encode_binary_to_header: unaligned remainder payload") {
	const std::vector<uint8_t> input = { 0x11, 0x22, 0x33, 0x44, 0x55 };
	auto res = encode_binary_to_header("sample", ".bin", input);

	CHECK(res.output_filename == "sample_bin_bin.h");
	CHECK(res.header_content.find("inline constexpr unsigned int SAMPLE_BIN_SIZE = 5;") != std::string::npos);
	CHECK(res.header_content.find("inline constexpr unsigned int SAMPLE_BIN_DATA[2] = {") != std::string::npos);
	CHECK(res.header_content.find("0xbbccddee") != std::string::npos);
	CHECK(res.header_content.find("0xffffffaa") != std::string::npos);
}

TEST_CASE("encode_binary_to_header: round-trip decoding matches ExportDriver logic") {
	const std::vector<uint8_t> original = { 'M', 'Z', 0x90, 0x00, 0x03, 0x00, 0x00 };
	auto res = encode_binary_to_header("xhunter1", ".sys", original);

	// Extract slot values
	uint32_t slot0 = 0;
	uint32_t slot1 = 0;
	std::memcpy(&slot0, original.data(), 4);
	slot0 ^= 0xFFFFFFFF;

	uint32_t rem_val = 0;
	for (size_t i = 0; i < 3; i++) {
		rem_val |= static_cast<uint32_t>(original[4 + i]) << (i * 8);
	}
	slot1 = rem_val ^ 0xFFFFFFFF;

	std::vector<uint32_t> raw_slots = { slot0, slot1 };
	std::vector<uint8_t> decoded(original.size());
	std::memcpy(decoded.data(), raw_slots.data(), original.size());

	for (auto& b : decoded) {
		b ^= 0xFF;
	}

	CHECK(decoded == original);
}

int main(int argc, char* argv[]) {
	doctest::Context context;
	context.applyCommandLine(argc, argv);
	const int test_res = context.run();
	if (context.shouldExit()) {
		return test_res;
	}

	std::vector<std::string> file_args;
	fs::path explicit_output;

	for (int i = 1; i < argc; i++) {
		std::string arg = argv[i];
		if (arg == "-o" || arg == "--output") {
			if (i + 1 < argc) {
				explicit_output = argv[++i];
			}
		} else if (!arg.starts_with('-')) {
			file_args.push_back(arg);
		}
	}

	if (file_args.empty() && !context.shouldExit()) {
		if (test_res != 0) {
			return test_res;
		}
		std::cout << "Usage: bin2header [options] <file1> [file2 ...]\n";
		std::cout << "Options:\n";
		std::cout << "  -o, --output <path>    Specify output file or directory\n";
		std::cout << "  --test, -dt            Run built-in test suite\n";
		return 0;
	}

	for (const auto& path_str : file_args) {
		process_file(path_str, explicit_output);
	}

	return test_res;
}
