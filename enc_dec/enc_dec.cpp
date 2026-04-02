// enc_dec.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <filesystem>
#include <fstream>
#include <format>

int main(int argc, char* argv[]) {
	//for (int i = 1; i < argc; i++) {
	//	printf("%s\n", argv[i]);
	//}

	//system("pause");
	//return 1;

	for (int i = 1; i < argc; i++) {
		std::string result;

		std::filesystem::path path(argv[i]);

		std::ifstream f(path, std::ios::binary);

		if (f.is_open()) {
			std::string filename = path.stem().string();
			std::string ext = path.extension().string();
			std::string varname = filename;

			std::replace(filename.begin(), filename.end(), '.', '_');
			std::replace(varname.begin(), varname.end(), '.', '_');
			ext.erase(0, 1); // Remove the leading dot from the extension

			std::string upper_filename = filename;
			std::string upper_ext = ext;
			std::string upper_varname = varname;

			std::transform(upper_filename.begin(), upper_filename.end(), upper_filename.begin(), [](unsigned char c) { return std::toupper(c); });
			std::transform(upper_ext.begin(), upper_ext.end(), upper_ext.begin(), [](unsigned char c) { return std::toupper(c); });
			std::transform(upper_varname.begin(), upper_varname.end(), upper_varname.begin(), [](unsigned char c) { return std::toupper(c); });

			std::string data;
			f.seekg(0, std::ios::end);
			data.resize(f.tellg());
			f.seekg(0, std::ios::beg);
			f.read(&data[0], data.size());
			f.close();

			const size_t dataSize = data.size();
			const size_t slotSize = dataSize / 4;
			const size_t remainderSize = dataSize % 4;
			const size_t totalSlotSize = slotSize + (remainderSize ? 1 : 0);

			result = "#pragma once\n\n";

			result += std::format("static const unsigned int {}_{}_SIZE = {};\n\n", upper_filename, upper_ext, data.size());

			result += std::format("static const unsigned int {}_{}_DATA[{}] = {{", upper_filename, upper_ext, totalSlotSize);

			for (size_t i = 0; i < slotSize; i += 4) {
				result += "\n\t";

				for (size_t l = 0; l < std::min<size_t>(slotSize - i, 4); l++) {
					result += std::format("0x{:08x}, ", *(uint32_t*)(&data[i * 4 + l * 4]) ^ 0xFFFFFFFF);
				}
			}

			if (remainderSize != 0) {
				uint32_t v = 0;

				if (slotSize % 4 == 0)
					result += "\n\t";

				for (size_t i = 0; i < remainderSize; i++)
					v |= ((uint32_t)(uint8_t)data[data.size() - remainderSize + i]) << (i * 8);

				result += std::format("0x{:08x}", (uint32_t)v ^ 0xFFFFFFFF);
			}

			result += "\n};";

			std::ofstream out(std::format("{}\\{}_{}_bin.h", path.parent_path().string(), filename, ext));
			if (out.is_open()) {
				out << result;
				out.close();
			}
		}
	}
}