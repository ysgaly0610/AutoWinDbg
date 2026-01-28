from pykd import *
import sys
import re
import time

def execute_dbg_command(command, silent_fail=True):
    try:
        result = dbgCommand(command)
        if not result:
            return f"[INFO] 命令 '{command}' 执行成功，但无输出"
        output = result.strip()
        if not output:
            return f"[INFO] 命令 '{command}' 执行成功，但无有效输出"
        return output
    except Exception as e:
        return f"[SKIP] 命令 '{command}' 执行失败: {str(e)}"

def extract_exception_info(analyze_output):
    """从 !analyze -v 中提取异常信息"""
    info = {
        'code': None, 
        'address': None, 
        'symbol': None,
        'fault_address': None,  # 访问违例的目标地址
        'instruction_address': None,  # 指令地址
        'module': None
    }
    lines = analyze_output.split('\n')
    for line in lines:
        if "EXCEPTION_CODE:" in line:
            info['code'] = line.split()[-1].lower()
        elif "FAULTING_IP:" in line or "EXCEPTION_ADDRESS:" in line:
            parts = line.split()
            if len(parts) >= 2:
                info['instruction_address'] = parts[-1]
                # 提取模块名
                if '!' in line:
                    info['module'] = line.split('!')[0].split()[-1]
        elif "SYMBOL_NAME:" in line:
            info['symbol'] = line.split()[-1]
        elif "EXCEPTION_PARAMETER1:" in line or "READ_ADDRESS:" in line or "WRITE_ADDRESS:" in line:
            # 这是访问违例时试图读写的地址
            parts = line.split()
            if len(parts) >= 2:
                info['fault_address'] = parts[-1]
    
    # 兼容旧代码
    if not info['address']:
        info['address'] = info['instruction_address']
    
    return info

def basic_user_analysis():
    print(f"\n{time.strftime('%H:%M:%S')} ===== 基础崩溃分析 (!analyze -v) =====")
    result = execute_dbg_command("!analyze -v")
    print(result)
    
    global g_exception_info
    g_exception_info = extract_exception_info(result)
    
    print(f"\n{time.strftime('%H:%M:%S')} ===== 异常记录 (.exr -1) =====")
    print(execute_dbg_command(".exr -1", silent_fail=True))
    
    print(f"\n{time.strftime('%H:%M:%S')} ===== 当前寄存器状态 (r) =====")
    print(execute_dbg_command("r", silent_fail=True))

def process_and_thread_info():
    print(f"\n{time.strftime('%H:%M:%S')} ===== 进程与线程信息 =====")
    print(f"\n----- 进程环境块 (PEB) -----")
    print(execute_dbg_command("!peb", silent_fail=True))
    
    print(f"\n----- 当前线程环境块 (TEB) -----")
    print(execute_dbg_command("!teb", silent_fail=True))
    
    print(f"\n----- 所有线程列表 (~*) -----")
    print(execute_dbg_command("~*", silent_fail=True))
    
def module_analysis():
    print(f"\n{time.strftime('%H:%M:%S')} ===== 模块分析 =====")
    print(f"\n----- 模块简略列表 (lm) -----")
    # 使用 lm 命令替代 lmv，lm 不会触发强制符号下载，速度极快
    print(execute_dbg_command("lm", silent_fail=True))
    
    # 不再全局执行 lmv，因为太慢了。
    # 详细信息将在后续的 stack_trace_analysis 中只针对崩溃相关的模块执行。
# def module_analysis():
#     print(f"\n{time.strftime('%H:%M:%S')} ===== 模块分析 =====")
#     print(f"\n----- 已加载模块简略列表 (lm) -----")
#     print(execute_dbg_command("lm", silent_fail=True))
    
#     print(f"\n----- 详细模块信息 (lmv) -----")
#     print(execute_dbg_command("lmv", silent_fail=True))

def memory_and_heap_analysis():
    print(f"\n{time.strftime('%H:%M:%S')} ===== 内存与堆分析 =====")
    print(f"\n----- 内存布局摘要 (!address -summary) -----")
    print(execute_dbg_command("!address -summary", silent_fail=True))
    
    print(f"\n----- 堆状态统计 (!heap -s) -----")
    print(execute_dbg_command("!heap -s", silent_fail=True))

def handle_analysis():
    print(f"\n{time.strftime('%H:%M:%S')} ===== 句柄分析 (!handle) =====")
    # 0xf 表示列出所有句柄的详细信息
    print(execute_dbg_command("!handle 0 0", silent_fail=True))

# def stack_trace_analysis():
#     print(f"\n{time.strftime('%H:%M:%S')} ===== 调用堆栈分析 =====")
#     print(f"\n----- 当前线程堆栈 (knL) -----")
#     # n: 显示行号, L: 隐藏源信息
#     stack_output = execute_dbg_command("knL", silent_fail=True)
#     print(stack_output)
    
#     print(f"\n----- 所有线程堆栈 (~* k) -----")
#     print(execute_dbg_command("~* k", silent_fail=True))

#     print(f"\n{time.strftime('%H:%M:%S')} ----- 查找堆栈中的关键模块 -----")
#     modules_seen = set()
#     for line in stack_output.split('\n'):
#         if '!' in line:
#             parts = line.split('!')
#             if len(parts) >= 2:
#                 # 提取模块名
#                 mod = parts[0].strip().split()[-1]
#                 # 排除系统核心库以减少噪音
#                 system_dlls = ('ntdll', 'kernel32', 'kernelbase', 'user32', 'msvcrt')
#                 if mod and mod not in modules_seen and not mod.lower().startswith(system_dlls):
#                     modules_seen.add(mod)
#                     print(f"\n-- 关键模块 {mod} 详细信息 --")
#                     print(execute_dbg_command(f"lmvm {mod}", silent_fail=True))

def stack_trace_analysis():
    print(f"\n{time.strftime('%H:%M:%S')} ===== 调用堆栈分析 =====")
    print(f"\n----- 当前线程堆栈 (knL) -----")
    stack_output = execute_dbg_command("knL", silent_fail=True)
    print(stack_output)
    
    print(f"\n----- 当前线程堆栈带参数 (kpL) -----")
    print(execute_dbg_command("kpL", silent_fail=True))
    
    print(f"\n----- 所有线程堆栈简要 (~* k 5) -----")
    print(execute_dbg_command("~* k 5", silent_fail=True))

    print(f"\n{time.strftime('%H:%M:%S')} ----- 针对性分析堆栈中的第三方模块 -----")
    modules_seen = set()
    system_prefixes = ('ntdll', 'kernel', 'msvcrt', 'user32', 'combase', 'rpcrt4', 'gdi32', 'imm32', 'advapi32')
    
    for line in stack_output.split('\n'):
        if '!' in line:
            try:
                parts = line.split('!')
                mod_part = parts[0].strip().split()[-1]
                mod_name = mod_part.lower()
                
                if mod_name and mod_name not in modules_seen:
                    if not any(mod_name.startswith(p) for p in system_prefixes):
                        modules_seen.add(mod_name)
                        print(f"\n[重点] 关键模块 {mod_name} 详细信息 (lmvm):")
                        print(execute_dbg_command(f"lmvm {mod_name}", silent_fail=True))
            except:
                continue

def mfc_specific_analysis():
    """MFC 应用程序特定分析"""
    print(f"\n{time.strftime('%H:%M:%S')} ===== MFC 应用程序分析 =====")
    
    print(f"\n----- MFC 窗口列表 (!dumpwindows) -----")
    print(execute_dbg_command("!dumpwindows", silent_fail=True))
    
    print(f"\n----- MFC 消息队列 (!msgq) -----")
    print(execute_dbg_command("!msgq", silent_fail=True))
    
    print(f"\n----- 当前消息 (dt MSG @esp) -----")
    print(execute_dbg_command("dt MSG @esp", silent_fail=True))
    
    print(f"\n----- GDI 对象泄漏检测 (!gdiusage) -----")
    print(execute_dbg_command("!gdiusage", silent_fail=True))
    
    print(f"\n----- USER 对象统计 (!handle 0 1 -t) -----")
    print(execute_dbg_command("!handle 0 1 -t", silent_fail=True))

def com_and_third_party_dll_analysis():
    """COM 组件和第三方 DLL 分析（运动控制、相机等）"""
    print(f"\n{time.strftime('%H:%M:%S')} ===== COM 组件与第三方 DLL 分析 =====")
    
    print(f"\n----- COM 接口泄漏 (!comcalls) -----")
    print(execute_dbg_command("!comcalls", silent_fail=True))
    
    print(f"\n----- 识别第三方硬件 DLL -----")
    lm_output = execute_dbg_command("lm", silent_fail=True)
    
    # 常见运动控制和相机厂商关键词
    hardware_keywords = [
        'motion', 'axis', 'servo', 'plc', 'ecat', 'ethercat',  # 运动控制
        'camera', 'vision', 'basler', 'hikvision', 'daheng', 'mindvision',  # 相机
        'halcon', 'opencv', 'mvs',  # 视觉库
        'advantech', 'googol', 'zte', 'inovance', 'delta',  # 控制卡厂商
        'usb', 'pci', 'pcie', 'serial', 'com'  # 通信接口
    ]
    
    third_party_modules = []
    for line in lm_output.split('\n'):
        line_lower = line.lower()
        for keyword in hardware_keywords:
            if keyword in line_lower:
                # 提取模块名
                parts = line.split()
                if len(parts) >= 3:
                    mod_name = parts[2] if len(parts) > 2 else parts[0]
                    if mod_name not in third_party_modules:
                        third_party_modules.append(mod_name)
                break
    
    if third_party_modules:
        print(f"\n[重点] 检测到 {len(third_party_modules)} 个疑似硬件相关 DLL:")
        for mod in third_party_modules[:10]:  # 最多显示 10 个
            print(f"\n--- 模块: {mod} ---")
            print(execute_dbg_command(f"lmvm {mod}", silent_fail=True))
    else:
        print("[INFO] 未检测到明显的硬件相关 DLL，显示所有非系统模块:")
        # 显示所有非微软的 DLL
        for line in lm_output.split('\n'):
            if '\\' in line and 'microsoft' not in line.lower() and 'windows' not in line.lower():
                parts = line.split()
                if len(parts) >= 3:
                    mod_name = parts[2] if len(parts) > 2 else parts[0]
                    print(f"\n--- 第三方模块: {mod_name} ---")
                    print(execute_dbg_command(f"lmvm {mod_name}", silent_fail=True))

def critical_section_analysis():
    """死锁和临界区分析（工业上位机常见问题）"""
    print(f"\n{time.strftime('%H:%M:%S')} ===== 死锁与临界区分析 =====")
    
    print(f"\n----- 临界区列表 (!locks) -----")
    print(execute_dbg_command("!locks", silent_fail=True))
    
    print(f"\n----- 临界区详细 (!cs -l) -----")
    print(execute_dbg_command("!cs -l", silent_fail=True))
    
    print(f"\n----- 等待链分析 (!analyze -v -hang) -----")
    print(execute_dbg_command("!analyze -v -hang", silent_fail=True))
    
    print(f"\n----- 所有线程等待状态 (~* k) -----")
    threads_output = execute_dbg_command("~*", silent_fail=True)
    print(threads_output)
    
    # 分析是否有线程在等待硬件响应
    print(f"\n----- 检查是否有线程卡在硬件调用 -----")
    for line in threads_output.split('\n'):
        if 'wait' in line.lower() or 'sleep' in line.lower() or 'suspend' in line.lower():
            print(f"[警告] {line}")

def exception_chain_analysis():
    """异常链和 SEH 分析"""
    print(f"\n{time.strftime('%H:%M:%S')} ===== 异常链分析 =====")
    
    print(f"\n----- 异常链 (!exchain) -----")
    print(execute_dbg_command("!exchain", silent_fail=True))
    
    print(f"\n----- C++ 异常 (!cppexr) -----")
    print(execute_dbg_command("!cppexr", silent_fail=True))
    
    # 针对常见的硬件调用异常
    exc_code = g_exception_info.get('code', '')
    if exc_code:
        print(f"\n----- 异常代码分析: {exc_code} -----")
        if 'c0000005' in exc_code:
            print("[分析] 访问违例 - 可能原因:")
            print("  1. 硬件 DLL 返回了无效指针")
            print("  2. 相机/运动控制卡断开连接后访问")
            print("  3. 多线程竞争访问硬件句柄")
            print("  4. DLL 版本不匹配")
        elif 'c000001d' in exc_code:
            print("[分析] 非法指令 - 可能原因:")
            print("  1. 硬件 DLL 与 CPU 指令集不兼容")
            print("  2. 代码段被破坏")
        elif 'c0000374' in exc_code:
            print("[分析] 堆损坏 - 可能原因:")
            print("  1. 硬件 DLL 内存管理错误")
            print("  2. 缓冲区溢出（图像数据、运动轨迹数据）")
        elif 'c00000fd' in exc_code:
            print("[分析] 栈溢出 - 可能原因:")
            print("  1. 递归调用过深")
            print("  2. 大数组分配在栈上（图像处理）")

def symbol_and_source_analysis():
    """符号和源码信息"""
    print(f"\n{time.strftime('%H:%M:%S')} ===== 符号与源码分析 =====")
    
    print(f"\n----- 符号路径 (.sympath) -----")
    print(execute_dbg_command(".sympath", silent_fail=True))
    
    print(f"\n----- 符号状态 (!sym noisy) -----")
    print(execute_dbg_command("!sym noisy", silent_fail=True))
    
    print(f"\n----- 源码路径 (.srcpath) -----")
    print(execute_dbg_command(".srcpath", silent_fail=True))

def unhandled_exception_filter():
    """未处理异常过滤器"""
    print(f"\n{time.strftime('%H:%M:%S')} ===== 未处理异常过滤器 =====")
    print(execute_dbg_command("!uniqstack", silent_fail=True))

def heap_corruption_check():
    """堆损坏检测（图像缓冲区、数据缓冲区）"""
    print(f"\n{time.strftime('%H:%M:%S')} ===== 堆损坏检测 =====")
    
    print(f"\n----- 堆验证 (!heap -x) -----")
    print(execute_dbg_command("!heap -x", silent_fail=True))
    
    # 如果异常代码是堆相关的
    exc_code = g_exception_info.get('code', '')
    if 'c0000374' in exc_code or 'c0000005' in exc_code:
        print(f"\n----- 堆详细分析 (!heap -p -a <addr>) -----")
        addr = g_exception_info.get('address')
        if addr:
            print(execute_dbg_command(f"!heap -p -a {addr}", silent_fail=True))
    
    print(f"\n----- 大内存分配检测（图像缓冲区泄漏）-----")
    print(execute_dbg_command("!heap -stat -h 0", silent_fail=True))

def vtable_analysis():
    """虚表分析（C++ 对象）"""
    print(f"\n{time.strftime('%H:%M:%S')} ===== 虚表分析 =====")
    
    # 尝试分析崩溃地址附近的虚表
    addr = g_exception_info.get('address')
    if addr and '0x' in addr:
        print(f"\n----- 虚表指针 (dps {addr}) -----")
        print(execute_dbg_command(f"dps {addr} L5", silent_fail=True))

def hardware_io_analysis():
    """硬件 I/O 和设备句柄分析"""
    print(f"\n{time.strftime('%H:%M:%S')} ===== 硬件 I/O 与设备句柄分析 =====")
    
    print(f"\n----- 文件句柄（可能包含设备句柄）-----")
    print(execute_dbg_command("!handle 0 f", silent_fail=True))
    
    print(f"\n----- 事件对象（硬件中断、同步）-----")
    print(execute_dbg_command("!handle 0 f Event", silent_fail=True))
    
    print(f"\n----- 互斥体（硬件访问互斥）-----")
    print(execute_dbg_command("!handle 0 f Mutant", silent_fail=True))
    
    print(f"\n----- 信号量（资源计数）-----")
    print(execute_dbg_command("!handle 0 f Semaphore", silent_fail=True))
    
    print(f"\n----- 线程句柄（工作线程）-----")
    print(execute_dbg_command("!handle 0 f Thread", silent_fail=True))

def last_error_analysis():
    """GetLastError 和系统错误分析"""
    print(f"\n{time.strftime('%H:%M:%S')} ===== 系统错误码分析 =====")
    
    print(f"\n----- 当前线程 LastError (!gle) -----")
    print(execute_dbg_command("!gle", silent_fail=True))
    
    print(f"\n----- 所有线程 LastError (!gle -all) -----")
    print(execute_dbg_command("!gle -all", silent_fail=True))

def deep_exception_address_analysis():
    """深度分析异常地址 - 核心诊断功能"""
    print(f"\n{time.strftime('%H:%M:%S')} ===== 异常地址深度分析 =====")
    
    instruction_addr = g_exception_info.get('instruction_address')
    fault_addr = g_exception_info.get('fault_address')
    exc_code = g_exception_info.get('code', '')
    module = g_exception_info.get('module')
    
    # ========== 1. 分析指令地址（崩溃发生的代码位置）==========
    if instruction_addr and '0x' in instruction_addr:
        print(f"\n{'='*60}")
        print(f"[指令地址] {instruction_addr} - 崩溃发生的代码位置")
        print(f"{'='*60}")
        
        print(f"\n----- 指令地址内存属性 (!address {instruction_addr}) -----")
        addr_info = execute_dbg_command(f"!address {instruction_addr}", silent_fail=True)
        print(addr_info)
        
        print(f"\n----- 指令反汇编（前后各10行）(ub {instruction_addr} L5; u {instruction_addr} L10) -----")
        print(execute_dbg_command(f"ub {instruction_addr} L5", silent_fail=True))
        print(f"\n>>> 崩溃指令位置 <<<")
        print(execute_dbg_command(f"u {instruction_addr} L10", silent_fail=True))
        
        print(f"\n----- 指令地址所属模块详细信息 -----")
        if module:
            print(execute_dbg_command(f"lmvm {module}", silent_fail=True))
        else:
            print(execute_dbg_command(f"lma {instruction_addr}", silent_fail=True))
        
        print(f"\n----- 指令地址符号信息 (ln {instruction_addr}) -----")
        symbol_info = execute_dbg_command(f"ln {instruction_addr}", silent_fail=True)
        print(symbol_info)
        
        # 检查是否在已知函数内
        if '+' in symbol_info or '!' in symbol_info:
            print("[分析] 崩溃发生在已识别的函数内")
        else:
            print("[警告] 崩溃地址无符号信息，可能是:")
            print("  1. 跳转到了无效代码区域")
            print("  2. 缺少符号文件（PDB）")
            print("  3. 动态生成的代码")
    
    # ========== 2. 分析故障地址（访问违例时试图访问的地址）==========
    if fault_addr and '0x' in fault_addr and fault_addr != instruction_addr:
        print(f"\n{'='*60}")
        print(f"[故障地址] {fault_addr} - 试图访问的内存地址")
        print(f"{'='*60}")
        
        print(f"\n----- 故障地址内存属性 (!address {fault_addr}) -----")
        fault_addr_info = execute_dbg_command(f"!address {fault_addr}", silent_fail=True)
        print(fault_addr_info)
        
        # 判断地址类型
        fault_addr_lower = fault_addr.lower()
        if fault_addr_lower in ['0x0', '0x00000000', '0x0000000000000000']:
            print("[诊断] 空指针访问 (NULL)")
            print("  可能原因:")
            print("  1. 对象未初始化就使用")
            print("  2. 硬件 DLL 返回了 NULL 但未检查")
            print("  3. 相机/运动控制卡断开后句柄失效")
        elif 'free' in fault_addr_info.lower() or 'reserve' in fault_addr_info.lower():
            print("[诊断] 访问已释放或未分配的内存")
            print("  可能原因:")
            print("  1. Use-After-Free（对象已释放）")
            print("  2. 野指针")
            print("  3. 硬件 DLL 内部错误")
        elif 'stack' in fault_addr_info.lower():
            print("[诊断] 访问栈内存")
            print("  可能原因:")
            print("  1. 栈溢出")
            print("  2. 访问已销毁的局部变量")
        elif 'heap' in fault_addr_info.lower():
            print("[诊断] 访问堆内存")
            print("  可能原因:")
            print("  1. 堆损坏")
            print("  2. 缓冲区越界（图像数据）")
        
        # 尝试读取故障地址内容
        print(f"\n----- 尝试读取故障地址内容 (db {fault_addr} L40) -----")
        fault_data = execute_dbg_command(f"db {fault_addr} L40", silent_fail=True)
        if 'memory access error' in fault_data.lower() or 'cannot' in fault_data.lower():
            print("[确认] 该地址不可访问，这就是崩溃原因")
        else:
            print(fault_data)
            print("[分析] 地址可读，可能是写入权限问题")
        
        # 检查是否在堆上
        print(f"\n----- 检查故障地址是否在堆上 (!heap -p -a {fault_addr}) -----")
        print(execute_dbg_command(f"!heap -p -a {fault_addr}", silent_fail=True))
    
    # ========== 3. 寄存器分析（查找相关地址）==========
    print(f"\n{'='*60}")
    print(f"[寄存器分析] 查找寄存器中的相关地址")
    print(f"{'='*60}")
    
    print(f"\n----- 当前寄存器值 (r) -----")
    reg_output = execute_dbg_command("r", silent_fail=True)
    print(reg_output)
    
    # 提取寄存器中的地址并分析
    print(f"\n----- 分析寄存器指向的内存 -----")
    import re
    # 匹配寄存器值（十六进制地址）
    reg_pattern = r'(r\w+|e\w+|rip|eip|rsp|esp|rbp|ebp)=([0-9a-f`]+)'
    registers = re.findall(reg_pattern, reg_output.lower())
    
    analyzed_addrs = set()
    for reg_name, reg_value in registers[:8]:  # 只分析前8个寄存器
        # 清理地址格式
        clean_addr = reg_value.replace('`', '')
        if len(clean_addr) >= 8 and clean_addr not in analyzed_addrs:
            analyzed_addrs.add(clean_addr)
            print(f"\n--- {reg_name.upper()} = 0x{clean_addr} ---")
            # 尝试解引用
            print(execute_dbg_command(f"dps 0x{clean_addr} L1", silent_fail=True))
    
    # ========== 4. 调用栈上下文分析 ==========
    print(f"\n{'='*60}")
    print(f"[调用栈上下文] 崩溃前的函数调用链")
    print(f"{'='*60}")
    
    print(f"\n----- 详细调用栈（带参数）(kP) -----")
    print(execute_dbg_command("kP", silent_fail=True))
    
    print(f"\n----- 栈帧详细信息 (.frame; dv) -----")
    # 显示前3个栈帧的局部变量
    for i in range(3):
        print(f"\n--- 栈帧 {i} 的局部变量 ---")
        print(execute_dbg_command(f".frame {i}; dv", silent_fail=True))

def image_buffer_analysis():
    """图像缓冲区和大数据块分析"""
    print(f"\n{time.strftime('%H:%M:%S')} ===== 图像缓冲区与大数据分析 =====")
    
    print(f"\n----- 查找大内存块（>1MB，可能是图像）-----")
    print(execute_dbg_command("!address -f:MEM_COMMIT -f:MEM_PRIVATE", silent_fail=True))

def analyze_user_dump():
    # ========== 核心分析 ==========
    # 1. 基础异常分析
    basic_user_analysis()
    
    # 2. 【重点】异常地址深度分析
    deep_exception_address_analysis()
    
    # 3. 堆栈详细溯源
    stack_trace_analysis()
    
    # ========== MFC 工业上位机专项 ==========
    # 4. MFC 特定分析
    mfc_specific_analysis()
    
    # 5. COM 和第三方硬件 DLL（运动控制、相机）
    com_and_third_party_dll_analysis()
    
    # 6. 硬件 I/O 和设备句柄
    hardware_io_analysis()
    
    # 7. 死锁和临界区（多线程硬件访问）
    critical_section_analysis()
    
    # 8. 系统错误码
    last_error_analysis()
    
    # ========== 内存问题排查 ==========
    # 9. 环境信息
    process_and_thread_info()
    
    # 10. 模块信息
    module_analysis()
    
    # 11. 内存与堆
    memory_and_heap_analysis()
    
    # 12. 堆损坏检测（图像缓冲区）
    heap_corruption_check()
    
    # 13. 图像缓冲区分析
    image_buffer_analysis()
    
    # 14. 句柄泄漏
    handle_analysis()
    
    # ========== 深度分析 ==========
    # 15. 异常链
    exception_chain_analysis()
    
    # 16. 虚表分析
    vtable_analysis()
    
    # 17. 符号信息
    symbol_and_source_analysis()
    
    # 18. 唯一堆栈
    unhandled_exception_filter()

if __name__ == "__main__":
    # 检查是否为内核模式，如果是则提示并退出
    if isKernelDebugging():
        print("错误: 检测到内核调试模式。此脚本已修改为【用户态】分析专用。")
        sys.exit(1)
        
    g_exception_info = {}
    print(f"==================================================")
    print(f"用户态崩溃自动化分析脚本")
    print(f"执行时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"==================================================")
    
    try:
        analyze_user_dump()
    except Exception as e:
        print(f"分析过程中出现异常: {str(e)}")
        
    print(f"\n{time.strftime('%H:%M:%S')} ===== 分析完成 =====")