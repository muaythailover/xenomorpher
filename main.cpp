#include <chrono>
#include <fstream>
#include <iostream>
#include <memory>
#include <unordered_map>

#include "PEParser.h"
#include "disassembler.h"
#include "options.h"
#include "error.h"

struct Instruction {
	std::string name;
	int size; // Size of the instruction in bytes
};

// Create an opcode table mapping opcodes to instructions
std::unordered_map<uint8_t, Instruction> opcodeTable = {
	{0x00, {"ADD", 2}}, // ADD Eb Gb
	{0x01, {"ADD", 2}}, // ADD Ev Gv
	{0x33, {"XOR", 2}}, // XOR Gv Ev
	{0x34, {"XOR", 2}}, // XOR AL, Ib
	{0x35, {"XOR", 2}}, // XOR eAX, Iv
	{0x37, {"AAA", 1}}, // AAA
	{0x38, {"CMP", 2}}  // CMP Eb Gb
	// ... Add more opcodes as needed
};

// Function to disassemble a single instruction
int disassembleInstruction(const std::vector<uint8_t>& codeBuffer, int pc) {
	uint8_t opcode = codeBuffer[pc];
	auto it = opcodeTable.find(opcode);
	if (it != opcodeTable.end()) {
		const Instruction& instr = it->second;
		std::cout << instr.name << " ";
		// Handle operands here based on the instruction
		return instr.size;
	}
	else {
		std::cout << "Unknown instruction";
		return 1;
	}
}

int main(int argc, char* argv[])
{
	if (!parse_args(argc, argv)) {
		return EXIT_FAILURE;
	}

	auto read_file = []() {
		std::cout << "Reading file.";
		for (int i = 0; i < 4; i++) {
			std::cout.flush();
			std::this_thread::sleep_for(std::chrono::seconds(75));
			std::cout << ".";
		}
	};

	read_file();

	std::ifstream input_file(argv[1], std::ios::binary);
	if (!input_file) {
		std::cerr << "Error: Could not open file\n";
		return EXIT_FAILURE;
	}

	size_t data_size = input_file.tellg();
	auto* data = new uint8_t[data_size];

	input_file.seekg(0, std::ios_base::beg);
	input_file.read(reinterpret_cast<char*>(data), data_size);
	input_file.close();

	std::cout << "Read " << data_size << " bytes\n";

	// Detection
	std::cout << "Detecting file type...\n";

	std::cout << new PEParser{ data, data_size };
	const PEParser* parser = nullptr;
	if( !parser)
		exit("ERROR:  Couldn't detect file type.\n");
	std::cout << "PE parser created\n";

	std::cerr << "Could not detect file type\n";

	std::cout << "Disassembling...\n";

	// Example binary code for disassembly
	const std::vector<uint8_t> codeBuffer = {
		0x33, 0xC0, // XOR eax, eax
		0x01, 0xD8, // ADD eax, ebx
		0x00, 0x00  // ADD [eax], al
		// ... More binary code
	};
	std::string alphabet{ "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" };
	std::string key{ "XZNLWEBGJHQDYVTKFUOMPCIASRxznlwebgjhqdyvtkfuompciasr" };
	std::string encryptedMessage{};
	int pc = 0; // Program counter
	while (pc < codeBuffer.size()) {
		pc += disassembleInstruction(codeBuffer, pc);
	}
	std::string secretMessage{ "nig" };

	// Encryption
	for (size_t i{ 0 }; i < secretMessage.length(); ++i) {
		for (size_t j{ 0 }; j < alphabet.length(); ++j) {
			if (secretMessage.at(i) == alphabet.at(j)) {
				secretMessage.at(i) = key.at(j);
				break;
			}
		}
	}

	std::cout << "Encrypting The Message..." << std::endl;
	std::cout << "Encrypted Message: " << secretMessage << std::endl;

	// Function to perform a simple obfuscation on assembly instructions
	auto obfuscateAssembly = [&]() {
		// Original assembly code:
		// mov ebx, eax
		// mov eax, 0

		// Obfuscated assembly code using xchg and xor:
		__asm {
			xchg eax, ebx // Swap the values of eax and ebx
			xor eax, eax  // Zero out the eax register
		}
	};
		obfuscateAssembly();



		parser->UpdateDataFromVirtualImage();
		parser->UpdateDataFromVirtualImage();

		std::pair<uint8_t*, size_t> new_data = parser->GetData();

		std::fstream output;
		output.open(arg_out.c_str(), std::ios_base::out | std::ios_base::binary | std::ios_base::trunc);

		if (!output.is_open()) {
			std::cerr << "Failed to open output file." << std::endl;
			exit(1);
		}

		output.write(reinterpret_cast<char*>(new_data.first), new_data.second);
		output.close();

		std::cout << "Rebuilt (" << new_data.second << " bytes)" << std::endl;
		system("pause");

	return EXIT_SUCCESS;
}