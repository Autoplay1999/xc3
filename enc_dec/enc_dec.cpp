// enc_dec.cpp : Utility tool to encode binary files into C++ header files.
//

#include <iostream>
#include <filesystem>
#include <fstream>
#include <format>
#include <vector>
#include <algorithm>
#include <cstring>
#include <cstdint>

namespace fs = std::filesystem;

static void process_file(const fs::path& path) {
	std::ifstream f(path, std::ios::binary | std::ios::ate);
	if (!f.is_open()) {
		std::cerr << std::format("[-] Failed to open: {}\n", path.string());
		return;
	}

	const auto file_size = f.tellg();
	if (file_size <= 0) {
		std::cerr << std::format("[-] Invalid or empty file: {}\n", path.string());
		return;
	}

	std::vector<uint8_t> data(static_cast<size_t>(file_size));
	f.seekg(0, std::ios::beg);
	f.read(reinterpret_cast<char*>(data.data()), data.size());
	f.close();

	std::string filename = path.stem().string();
	std::string ext = path.has_extension() ? path.extension().string().substr(1) : "";
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

	const fs::path out_path = path.parent_path() / std::format("{}_{}_bin.h", filename, ext);
	std::ofstream out(out_path, std::ios::trunc);
	if (out.is_open()) {
		out << result;
		out.close();
		std::cout << std::format("[+] Generated: {}\n", out_path.string());
	} else {
		std::cerr << std::format("[-] Failed to write output: {}\n", out_path.string());
	}
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		std::cout << "Usage: enc_dec <file1> [file2 ...]\n";
		return 1;
	}

	for (int i = 1; i < argc; i++) {
		process_file(argv[i]);
	}

	return 0;
}
