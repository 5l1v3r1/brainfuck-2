#include <iostream>
#include <fstream>
#include <Windows.h>
#include <vector>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <chrono>

enum class ILOp
{
	AddPtr, 
	SubPtr, 
	AddVal, 
	SubVal,
	In,
	Out, 
	LoopBegin, 
	LoopEnd, 
	Nop, 
	MovVal
};

struct ILInst
{
	ILOp op;
	uint32_t value;
	uint32_t offset;
};

class BrainfuckCompiler
{
	struct LoopData
	{
		size_t il_begin, il_end;
		uint64_t bytecode_begin;
		uint64_t bytecode_jz_instr;
	};

	std::vector<uint8_t>  bytecode;
	std::vector<ILInst>   il;
	std::vector<LoopData> loop_data;

	void push_bytecode(const std::initializer_list<uint8_t>& list)
	{
		bytecode.insert(bytecode.end(), list);
	}

	bool link_loops()
	{
		std::vector<uint64_t> stack;

		for (size_t i = 0; i < il.size(); ++i)
		{
			switch (il[i].op)
			{
			case ILOp::LoopBegin:
				stack.emplace_back(i);
				break;

			case ILOp::LoopEnd:
				if (stack.empty())
					return false;

				const auto begin = stack.back();
				stack.pop_back();

				loop_data.emplace_back(LoopData{ begin, i });
				break;
			}
		}

		return stack.empty();
	}

	void optimize_merge_arithmetic()
	{
		std::vector<ILInst> optimized_il;

		bool is_in_streak = false;
		uint32_t streak_count = 0;
		ILOp streak_op = ILOp::Nop;

		for (size_t i = 0; i < il.size(); ++i)
		{
			const auto& inst = il[i];
			const auto op = inst.op;

			if (is_in_streak)
			{
				if (streak_op == op)
				{
					streak_count++;
				}
				else
				{
					optimized_il.emplace_back(ILInst{ streak_op , streak_count });
					is_in_streak = false;
				}
			}

			if (!is_in_streak)
			{
				if (op == ILOp::AddPtr || op == ILOp::SubPtr || op == ILOp::AddVal || op == ILOp::SubVal)
				{
					is_in_streak = true;
					streak_count = 1;
					streak_op = op;

				}
				else
				{
					optimized_il.emplace_back(inst);
				}
			}

		}

		if (is_in_streak)
			optimized_il.emplace_back(ILInst{ streak_op , streak_count });

		il = optimized_il;
	}

	void optimize_replace_patterns()
	{
		std::vector<ILInst> optimized_il;

		for (size_t i = 0; i < il.size(); ++i)
		{
			if (i + 2 < il.size() &&
				il[i].op == ILOp::LoopBegin &&
				(il[i + 1].op == ILOp::SubVal || il[i + 1].op == ILOp::AddVal) &&
				il[i + 2].op == ILOp::LoopEnd)
			{
				if (il[i + 1].value == 1)
				{
					uint8_t value = 0;
					if (i + 3 < il.size() && il[i + 3].op == ILOp::AddVal)
					{
						value = il[i + 3].value;
						i += 1;
					}

					optimized_il.emplace_back(ILInst{ ILOp::MovVal, value });
					i += 2;
					continue;
				}
			}


			optimized_il.emplace_back(il[i]);
		}

		il = optimized_il;
	}

	void optimize_buffer_moves()
	{
		std::vector<ILInst> optimized_il;

		int32_t current_diff = 0;
		for (size_t i = 0; i < il.size(); ++i)
		{
			const auto& inst = il[i];
			const auto op = inst.op;

			if (op == ILOp::AddPtr)
			{
				current_diff += inst.value;
			}
			else if (op == ILOp::SubPtr)
			{
				current_diff -= inst.value;
			}
			else if (op == ILOp::AddVal || op == ILOp::SubVal || op == ILOp::Out || op == ILOp::In || op == ILOp::MovVal)
			{
				auto new_inst = inst;
				new_inst.offset = current_diff;
				optimized_il.emplace_back(new_inst);
			}
			else
			{
				if (current_diff > 0)
					optimized_il.emplace_back(ILInst{ ILOp::AddPtr, uint32_t(current_diff) });
				else if (current_diff < 0)
					optimized_il.emplace_back(ILInst{ ILOp::SubPtr, uint32_t(-current_diff) });

				optimized_il.emplace_back(inst);
				current_diff = 0;
			}
		}

		il = optimized_il;
	}

	void optimize_il()
	{
		constexpr bool DEBUG_INFO = true;

		{
			const auto before = il.size();
			optimize_merge_arithmetic();
			if (DEBUG_INFO) std::cout << "Merged arithmetics: " << before << " -> " << il.size() << ".\n";
		}

		{
			const auto before = il.size();
			optimize_replace_patterns();
			if (DEBUG_INFO) std::cout << "Replaced patterns: " << before << " -> " << il.size() << ".\n";
		}

		{
			const auto before = il.size();
			optimize_buffer_moves();
			if (DEBUG_INFO) std::cout << "Optimized buffer moves: " << before << " -> " << il.size() << ".\n";
		}
	}

	void generate_prologue()
	{
		push_bytecode({ 0x53, 0x56, 0x57 });        // push rbx; push rsi; push rdi
		push_bytecode({ 0x48, 0x89, 0xCB });        // mov rbx, rcx
		push_bytecode({ 0x48, 0x89, 0xD6 });        // mov rsi, rdx
		push_bytecode({ 0x4C, 0x89, 0xC7 });        // mov rdi, r8
		push_bytecode({ 0x48, 0x83, 0xEC, 0x20 });  // sub rsp, 0x20
	}

	void split_addsub(const std::initializer_list<uint8_t>& bytecode_begin, uint8_t count)
	{
		for (uint32_t i = 0; i < (count / 256); ++i)
		{
			push_bytecode(bytecode_begin);
			push_bytecode({ 0xFF });
		}

		push_bytecode(bytecode_begin);
		push_bytecode({ uint8_t(count % 256) });
	}

	void handle_addptr(size_t il_offset, const ILInst& inst)
	{
		if (inst.value == 1) push_bytecode({ 0x48, 0xFF, 0xC3 }); // inc rbx
		else split_addsub({ 0x48, 0x83, 0xC3 }, inst.value); // add rbx, ??
	}

	void handle_subptr(size_t il_offset, const ILInst& inst)
	{
		if (inst.value == 1) push_bytecode({ 0x48, 0xFF, 0xCB }); // dec rbx
		else split_addsub({ 0x48, 0x83, 0xEB }, inst.value); // sub rbx, ??
	}

	void handle_addval(size_t il_offset, const ILInst& inst)
	{
		if (inst.offset == 0)
		{
			if (inst.value == 1) push_bytecode({ 0xFE, 0x03 }); // inc byte ptr [rbx]
			else split_addsub({ 0x80, 0x03 }, inst.value); // add byte ptr [rbx], imm8
		}
		else if (int32_t(inst.offset) > -125 && int32_t(inst.offset) < 125)
		{
			if (inst.value == 1) push_bytecode({ 0xFE, 0x43, uint8_t(inst.offset) }); // inc byte ptr [rbx+imm8]
			else split_addsub({ 0x80, 0x43, uint8_t(inst.offset) }, inst.value); // add byte ptr [rbx+imm8], imm8
		}
		else
		{
			const auto s = (const uint8_t*)&inst.offset;
			if (inst.value == 1) push_bytecode({ 0xFE, 0x83, s[0], s[1], s[2], s[3] }); // inc byte ptr [rbx+imm32]
			else split_addsub({ 0x80, 0x83, s[0], s[1], s[2], s[3] }, inst.value); // add byte ptr [rbx+imm32], imm8
		}
	}

	void handle_subval(size_t il_offset, const ILInst& inst)
	{
		if (inst.offset == 0)
		{
			if (inst.value == 1) push_bytecode({ 0xFE, 0x0B }); // dec byte ptr [rbx]
			else split_addsub({ 0x80, 0x2B }, inst.value); // sub byte ptr [rbx], imm8
		}
		else if (int32_t(inst.offset) > -125 && int32_t(inst.offset) < 125)
		{
			if (inst.value == 1) push_bytecode({ 0xFE, 0x4B, uint8_t(inst.offset) }); // dec byte ptr [rbx+imm8]
			else split_addsub({ 0x80, 0x6B, uint8_t(inst.offset) }, inst.value); // sub byte ptr [rbx+imm8], imm8
		}
		else
		{
			const auto s = (const uint8_t*)&inst.offset;
			if (inst.value == 1) push_bytecode({ 0xFE, 0x8B, s[0], s[1], s[2], s[3] }); // dec byte ptr [rbx+imm32]
			else split_addsub({ 0x80, 0xAB, s[0], s[1], s[2], s[3] }, inst.value); // sub byte ptr [rbx+imm32], imm8
		}
	}

	void handle_movval(size_t il_offset, const ILInst& inst)
	{
		if (inst.offset == 0)
		{
			push_bytecode({ 0xC6, 0x03, uint8_t(inst.value % 256) }); // mov byte ptr [rbx], imm8
		}
		else if (int32_t(inst.offset) > -125 && int32_t(inst.offset) < 125)
		{
			push_bytecode({ 0xC6, 0x43, uint8_t(inst.offset), uint8_t(inst.value % 256) }); // mov byte ptr [rbx+imm8], imm8
		}
		else
		{
			const auto s = (const uint8_t*)&inst.offset;
			push_bytecode({ 0xC6, 0x83, s[0], s[1], s[2], s[3], uint8_t(inst.value % 256) }); // mov byte ptr [rbx+imm32], imm8
		}
	}

	void handle_out(size_t il_offset, const ILInst& inst)
	{
		if (inst.offset == 0)
		{
			push_bytecode({ 0x8A, 0x0B }); // mov cl, byte ptr [rbx]
		}
		else if (int32_t(inst.offset) > -125 && int32_t(inst.offset) < 125)
		{
			push_bytecode({ 0x8A, 0x4B , uint8_t(inst.offset) }); // mov cl, byte ptr [rbx+imm8]
		}
		else
		{
			const auto s = (const uint8_t*)&inst.offset;
			push_bytecode({ 0x8A, 0x8B, s[0], s[1], s[2], s[3] }); // mov cl, byte ptr [rbx+imm32]
		}

		push_bytecode({ 0xFF, 0xD6 }); // call rsi
	}

	void handle_in(size_t il_offset, const ILInst& inst)
	{
		push_bytecode({ 0xFF, 0xD7 }); // call rdi

		if (inst.offset == 0)
		{
			push_bytecode({ 0x88, 0x03 }); // mov byte ptr [rbx], al
		}
		else if (int32_t(inst.offset) > -125 && int32_t(inst.offset) < 125)
		{
			push_bytecode({ 0x88, 0x43 , uint8_t(inst.offset) }); // mov byte ptr [rbx+imm8], al
		}
		else
		{
			const auto s = (const uint8_t*)&inst.offset;
			push_bytecode({ 0x88, 0x83, s[0], s[1], s[2], s[3] }); // mov byte ptr [rbx+imm32], al
		}
	}

	bool handle_loop_begin(size_t il_offset, const ILInst& inst)
	{
		const auto found = std::find_if(loop_data.begin(), loop_data.end(), [&](const LoopData& data)
		{
			return data.il_begin == il_offset;
		});

		if (found != loop_data.end())
		{
			found->bytecode_begin = bytecode.size();
			push_bytecode({ 0x80, 0x3B, 0x00 }); // cmp byte ptr [rbx], 0

			found->bytecode_jz_instr = bytecode.size();
			push_bytecode({ 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00 }); // jz ???
		}
		else
		{
			std::cout << "Matching loop failed.\n";
			return false;
		}

		return true;
	}

	bool handle_loop_end(size_t il_offset, const ILInst& inst)
	{
		const auto found = std::find_if(loop_data.begin(), loop_data.end(), [&](const LoopData& info)
		{
			return info.il_end == il_offset;
		});

		if (found != loop_data.end())
		{
			const auto jmpback_rel32 = int32_t(found->bytecode_begin) - int32_t(bytecode.size()) - 5;
			const auto jmp_begin = bytecode.size();

			if (jmpback_rel32 < 120 && jmpback_rel32 > -120)
			{
				const auto jmpback_rel8 = int32_t(found->bytecode_begin) - int32_t(bytecode.size()) - 2;
				push_bytecode({ 0xEB, 0x00 }); // jmp ??
				*(uint8_t*)(bytecode.data() + jmp_begin + 1) = jmpback_rel8;
			}
			else
			{
				push_bytecode({ 0xE9, 0x00, 0x00, 0x00, 0x00 }); // jmp ??
				*(uint32_t*)(bytecode.data() + jmp_begin + 1) = jmpback_rel32;
			}

			const auto jz_rel32 = int32_t(bytecode.size() - int32_t(found->bytecode_jz_instr)) - 6;
			*(uint32_t*)(bytecode.data() + found->bytecode_jz_instr + 2) = jz_rel32;
		}
		else
		{
			std::cout << "Matching loop failed.\n";
			return false;
		}

		return true;
	}

	bool generate_bytecode_from_il()
	{
		for (size_t i = 0; i < il.size(); ++i)
		{
			const auto& inst = il[i];

			switch (inst.op)
			{
			case ILOp::AddPtr: handle_addptr(i, inst); break;
			case ILOp::SubPtr: handle_subptr(i, inst); break;
			case ILOp::AddVal: handle_addval(i, inst); break;
			case ILOp::SubVal: handle_subval(i, inst); break;
			case ILOp::MovVal: handle_movval(i, inst); break;

			case ILOp::LoopBegin: if (!handle_loop_begin(i, inst)) { return false; } break;
			case ILOp::LoopEnd:   if (!handle_loop_end(i, inst)) { return false; } break;

			case ILOp::In:  handle_in(i, inst);  break;
			case ILOp::Out: handle_out(i, inst); break;

			}
		}

		return true;
	}

	void generate_epilogue()
	{
		push_bytecode({ 0x48, 0x83, 0xC4, 0x20 });	// add rsp, 0x20
		push_bytecode({ 0x5F, 0x5E, 0x5B });		// pop rdi; pop rsi; pop rbx
		push_bytecode({ 0xC3 });					// ret
	}

public:
	bool compile()
	{
		optimize_il();

		if (!link_loops())
		{
			std::cout << "Unmatched parentheses.\n";
			return false;
		}

		generate_prologue();

		if (!generate_bytecode_from_il())
			return false;

		generate_epilogue();

		return true;
	}

	void handle_char(char c)
	{
		const auto push_inst = [this](const ILInst& inst) { il.emplace_back(inst); };

		switch (c)
		{
		case '>': push_inst({ ILOp::AddPtr, 1 }); break;
		case '<': push_inst({ ILOp::SubPtr, 1 }); break;
		case '+': push_inst({ ILOp::AddVal, 1 }); break;
		case '-': push_inst({ ILOp::SubVal, 1 }); break;
		case '.': push_inst({ ILOp::Out });       break;
		case ',': push_inst({ ILOp::In });        break;
		case '[': push_inst({ ILOp::LoopBegin }); break;
		case ']': push_inst({ ILOp::LoopEnd });   break;
		default: break;
		}
	}

	const std::vector<uint8_t>& get_bytecode_vec() const
	{
		return bytecode;
	}

	const uint8_t* get_bytecode()      const { return bytecode.data(); }
	size_t         get_bytecode_size() const { return bytecode.size(); }
};

struct Import
{
	std::string name;
	uint32_t	rva_to_address;
};

struct Module
{
	std::string			name;
	std::vector<Import> imports;
};

std::vector<uint8_t> create_import_section(uint32_t import_section_offset, std::vector<Module>& module_imports)
{
	std::vector<uint8_t> buffer;

	const auto alloc = [&](size_t allocation_size, size_t allocation_alignment)
	{
		const auto previous_size = buffer.size();
		buffer.resize(previous_size + allocation_size + allocation_alignment - 1);

		return (previous_size + (allocation_alignment - 1)) &
			~(uintptr_t)(allocation_alignment - 1);
	};

	alloc(sizeof(IMAGE_IMPORT_DESCRIPTOR) * (module_imports.size() + 1), 8);

	for (size_t i = 0; i < module_imports.size(); ++i)
	{
		auto& module = module_imports[i];
		const auto& module_name = module.name;

		const auto name_offset = alloc(module_name.size() + 1, 1);
		strcpy_s((char*)(buffer.data() + name_offset), module_name.size() + 1, module_name.c_str());

		const auto original_thunk_offset = alloc(8 * (module.imports.size() + 1), 8);
		for (size_t j = 0; j < module.imports.size(); ++j)
		{
			auto& import = module.imports[j];
			const auto& import_name = import.name;

			const auto ibn_offset = alloc(import_name.size() + 3, 1);
			strcpy_s((char*)(buffer.data() + ibn_offset + 2), import_name.size() + 1, import_name.c_str());
			*(uint64_t*)(buffer.data() + original_thunk_offset + j * 8) = import_section_offset + ibn_offset;

			import.rva_to_address = import_section_offset + original_thunk_offset + j * 8;
		}

		PIMAGE_IMPORT_DESCRIPTOR descriptor = PIMAGE_IMPORT_DESCRIPTOR(buffer.data()) + i;
		descriptor->Name = import_section_offset + name_offset;
		descriptor->ForwarderChain = -1;
		descriptor->OriginalFirstThunk = import_section_offset + original_thunk_offset;
		descriptor->FirstThunk = import_section_offset + original_thunk_offset;
	}

	return buffer;
}

void initialize_import_section(uint8_t* image, PIMAGE_NT_HEADERS nt_header,
	uint32_t import_section_offset, const std::vector<uint8_t>& import_section)
{
	const auto import_directory = &nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	import_directory->VirtualAddress = import_section_offset;
	import_directory->Size = sizeof(IMAGE_IMPORT_DESCRIPTOR);

	memcpy(image + import_section_offset, import_section.data(), import_section.size());
}

void generate_pe(const std::string& filename, const std::vector<uint8_t>& bytecode)
{
	const auto code_size = 0x2000 + ((bytecode.size() + 0xFFF) & ~uint64_t(0xFFF));
	const auto image_size = 0x2000 + code_size;

	const auto import_section_offset = 0x1000;
	const auto code_start = 0x2000;

	Module kernel32_mod{ "kernel32.dll" };
	kernel32_mod.imports.emplace_back(Import{ "WriteConsoleA" });
	kernel32_mod.imports.emplace_back(Import{ "GetStdHandle" });
	kernel32_mod.imports.emplace_back(Import{ "ExitProcess" });
	kernel32_mod.imports.emplace_back(Import{ "VirtualAlloc" });
	kernel32_mod.imports.emplace_back(Import{ "ReadConsoleA" });

	std::vector<Module> module_imports;
	module_imports.emplace_back(kernel32_mod);

	const auto image = (uint8_t*)VirtualAlloc(nullptr, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (image)
	{
		const auto dos_header = (IMAGE_DOS_HEADER*)image;
		memset(dos_header, 0x00, sizeof(IMAGE_DOS_HEADER));

		dos_header->e_magic = IMAGE_DOS_SIGNATURE;
		dos_header->e_lfanew = sizeof(IMAGE_DOS_HEADER);

		const auto nt_header = (IMAGE_NT_HEADERS64*)(image + dos_header->e_lfanew);
		memset(nt_header, 0x00, sizeof(IMAGE_NT_HEADERS64));

		nt_header->Signature = IMAGE_NT_SIGNATURE;

		const auto file_header = &nt_header->FileHeader;
		file_header->Machine = IMAGE_FILE_MACHINE_AMD64;
		file_header->NumberOfSections = 2;
		file_header->SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
		file_header->Characteristics = IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE_EXECUTABLE_IMAGE;

		const auto opt_header = &nt_header->OptionalHeader;
		opt_header->Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
		opt_header->SizeOfCode = code_size;
		opt_header->SizeOfInitializedData = 0x1000;
		opt_header->SizeOfUninitializedData = 0;
		opt_header->AddressOfEntryPoint = 0x2000;
		opt_header->BaseOfCode = 0x2000;
		opt_header->ImageBase = 0x140000000;
		opt_header->SectionAlignment = 0x1000;
		opt_header->FileAlignment = 0x1000;
		opt_header->MajorOperatingSystemVersion = 6;
		opt_header->MajorSubsystemVersion = 6;
		opt_header->SizeOfImage = image_size;
		opt_header->SizeOfHeaders = dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER) * file_header->NumberOfSections;
		opt_header->Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
		opt_header->DllCharacteristics = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_NX_COMPAT | IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE | IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
		opt_header->SizeOfStackReserve = 0x100000;
		opt_header->SizeOfStackCommit = 0x1000;
		opt_header->SizeOfHeapReserve = 0x100000;
		opt_header->SizeOfHeapCommit = 0x1000;
		opt_header->NumberOfRvaAndSizes = 2;

		const auto idata_section = IMAGE_FIRST_SECTION(nt_header) + 0;
		memset(idata_section, 0x00, sizeof(IMAGE_SECTION_HEADER));

		const auto text_section = IMAGE_FIRST_SECTION(nt_header) + 1;
		memset(text_section, 0x00, sizeof(IMAGE_SECTION_HEADER));

		{
			const uint64_t name = uint64_t('adi.') | (uint64_t('at') << 32);
			memcpy(idata_section->Name, (const uint8_t*)&name, sizeof(name));

			idata_section->Misc.VirtualSize = 0x1000;
			idata_section->VirtualAddress = 0x1000;
			idata_section->SizeOfRawData = 0x1000;
			idata_section->PointerToRawData = 0x1000;
			idata_section->Characteristics = IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;
		}

		{
			const uint64_t name = uint64_t('xet.') | (uint64_t('t') << 32);
			memcpy(text_section->Name, (const uint8_t*)&name, sizeof(name));

			text_section->Misc.VirtualSize = code_size;
			text_section->VirtualAddress = 0x2000;
			text_section->SizeOfRawData = code_size;
			text_section->PointerToRawData = 0x2000;
			text_section->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE;
		}

		const auto buffer = create_import_section(import_section_offset, module_imports);
		initialize_import_section(image, nt_header, import_section_offset, buffer);

		const uint8_t begin_shellcode[] =
		{
			0x4C, 0x8D, 0x3D, 0xF9, 0xFF, 0xFF, 0xFF,                // lea r15, [rel start]
			0xE9, 0xA7, 0x00, 0x00, 0x00,                            // jmp skip
		};

		std::vector<uint8_t> code;
		code.insert(code.end(), std::begin(begin_shellcode), std::end(begin_shellcode));

		for (const auto& import : module_imports[0].imports)
		{
			uint32_t value = import.rva_to_address - code_start;
			const auto s = (const uint8_t*)(&value);

			code.emplace_back(s[0]); code.emplace_back(s[1]);
			code.emplace_back(s[2]); code.emplace_back(s[3]);
		}

		const uint8_t end_shellcode[] =
		{
			0x48, 0x63, 0x05, 0xE5, 0xFF, 0xFF, 0xFF,                // movsx rax, dword [rel WriteConsoleAOffset]
			0x42, 0xFF, 0x24, 0x38,                                  // jmp [rax + r15]
			0x48, 0x63, 0x05, 0xDE, 0xFF, 0xFF, 0xFF,                // movsx rax, dword [rel GetStdHandleOffset]
			0x42, 0xFF, 0x24, 0x38,                                  // jmp [rax + r15]
			0x48, 0x63, 0x05, 0xD7, 0xFF, 0xFF, 0xFF,                // movsx rax, dword [rel ExitProcessOffset]
			0x42, 0xFF, 0x24, 0x38,                                  // jmp [rax + r15]
			0x48, 0x63, 0x05, 0xD0, 0xFF, 0xFF, 0xFF,                // movsx rax, dword [rel VirtualAllocOffset]
			0x42, 0xFF, 0x24, 0x38,                                  // jmp [rax + r15]
			0x48, 0x63, 0x05, 0xC9, 0xFF, 0xFF, 0xFF,                // movsx rax, dword [rel ReadConsoleAOffset]
			0x42, 0xFF, 0x24, 0x38,                                  // jmp [rax + r15]
			0x48, 0x83, 0xEC, 0x48,                                  // sub rsp, 0x48
			0x88, 0x4C, 0x24, 0x28,                                  // mov byte [rsp+0x28], cl
			0x4C, 0x89, 0xF1,                                        // mov rcx, r14
			0x48, 0x8D, 0x54, 0x24, 0x28,                            // lea rdx, [rsp+0x28]
			0x41, 0xB8, 0x01, 0x00, 0x00, 0x00,                      // mov r8d, 1
			0x4C, 0x8D, 0x4C, 0x24, 0x30,                            // lea r9 , [rsp+0x30]
			0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00,    // mov qword [rsp+0x20], 0
			0xE8, 0xA0, 0xFF, 0xFF, 0xFF,                            // call WriteConsoleA
			0x48, 0x83, 0xC4, 0x48,                                  // add rsp, 0x48
			0xC3,                                                    // ret
			0x48, 0x83, 0xEC, 0x48,                                  // sub rsp, 0x48
			0x4C, 0x89, 0xE9,                                        // mov rcx, r13
			0x48, 0x8D, 0x54, 0x24, 0x28,                            // lea rdx, [rsp+0x28]
			0x41, 0xB8, 0x01, 0x00, 0x00, 0x00,                      // mov r8d, 1
			0x4C, 0x8D, 0x4C, 0x24, 0x30,                            // lea r9 , [rsp+0x30]
			0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00,    // mov qword [rsp+0x20], 0
			0xE8, 0xA2, 0xFF, 0xFF, 0xFF,                            // call ReadConsoleA
			0x8A, 0x44, 0x24, 0x28,                                  // mov al, byte [rsp+0x28]
			0x48, 0x83, 0xC4, 0x48,                                  // add rsp, 0x48
			0xC3,                                                    // ret
			0x48, 0x83, 0xEC, 0x28,                                  // sub rsp, 0x28
			0x48, 0xC7, 0xC1, 0xF5, 0xFF, 0xFF, 0xFF,                // mov rcx, -11
			0xE8, 0x68, 0xFF, 0xFF, 0xFF,                            // call GetStdHandle
			0x49, 0x89, 0xC6,                                        // mov r14, rax
			0x48, 0xC7, 0xC1, 0xF6, 0xFF, 0xFF, 0xFF,                // mov rcx, -10
			0xE8, 0x59, 0xFF, 0xFF, 0xFF,                            // call GetStdHandle
			0x49, 0x89, 0xC5,                                        // mov r13, rax
			0x31, 0xC9,                                              // xor ecx, ecx
			0xBA, 0x00, 0x00, 0x05, 0x00,                            // mov rdx, 0x50000
			0x41, 0xB8, 0x00, 0x30, 0x00, 0x00,                      // mov r8, 0x3000 ; MEM_COMMIT | MEM_RESERVE
			0x41, 0xB9, 0x04, 0x00, 0x00, 0x00,                      // mov r9, 0x4 ; PAGE_READWRITE
			0xE8, 0x54, 0xFF, 0xFF, 0xFF,                            // call VirtualAlloc
			0x48, 0x89, 0xC1,                                        // mov rcx, rax
			0x48, 0x8D, 0x15, 0x60, 0xFF, 0xFF, 0xFF,                // lea rdx, [rel putchar]
			0x4C, 0x8D, 0x05, 0x87, 0xFF, 0xFF, 0xFF,                // lea r8, [rel getchar]
			0xE8, 0x0D, 0x00, 0x00, 0x00,                            // call actual_entrypoint
			0xE8, 0x7D, 0xFF, 0xFF, 0xFF,                            // call getchar
			0x48, 0x31, 0xC9,                                        // xor rcx, rcx
			0xE8, 0x26, 0xFF, 0xFF, 0xFF,                            // call ExitProcess
		};

		code.insert(code.end(), std::begin(end_shellcode), std::end(end_shellcode));
		code.insert(code.end(), std::begin(bytecode), std::end(bytecode));

		memcpy(image + code_start, code.data(), code.size());

		std::ofstream output_file(filename, std::ios::binary);
		if (output_file)
		{
			output_file.write((const char*)image, image_size);
			output_file.close();
		}
	}
}

int main()
{
	std::cout.sync_with_stdio(false);

	constexpr auto code_filename = "code.txt";
	constexpr auto bytecode_filename = "bytecode.bin";

	BrainfuckCompiler compiler;
	std::ifstream     code_file(code_filename);

	if (code_file)
	{
		std::stringstream buffer_stream;
		buffer_stream << code_file.rdbuf();

		const auto file_contents = buffer_stream.str();
		for (const auto c : file_contents)
		{
			compiler.handle_char(c);
		}

		if (compiler.compile())
		{
			const auto brainfuck_buffer_size = 0x20000;
			const auto bytecode_size = compiler.get_bytecode_size();
			const auto bytecode = compiler.get_bytecode();

			std::ofstream output_file(bytecode_filename, std::ios::binary);
			if (output_file)
			{
				output_file.write((const char*)bytecode, bytecode_size);
				output_file.close();
			}

			generate_pe("compiled.exe", compiler.get_bytecode_vec());
			std::cout << "Compiled file.\n";
		}
		else
		{
			std::cout << "Compilation failed.\n";
		}
	}
	else
	{
		std::cout << "Loading file failed.\n";
	}

	std::cin.get();
}

