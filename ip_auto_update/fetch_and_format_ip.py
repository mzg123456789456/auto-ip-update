import requests
import json
import re
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time
from urllib3.exceptions import InsecureRequestWarning
import socket

# 禁用SSL警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

API_CONFIG_FILE = 'api_config.json'
OUTPUT_FILE = '优选ip.txt'

# 线程锁，用于安全写入结果
lock = threading.Lock()

def is_valid_ip_line(line):
    """验证IP行，排除IPv6地址"""
    # 检查是否包含IPv6地址（排除）
    ipv6_match = re.match(r'^\[?[0-9a-fA-F:]+\]?(:\d+)?(#|\s|\||$)', line)
    if ipv6_match:
        return False  # 排除IPv6
    
    # 只保留IPv4地址
    if re.match(r'^(\d+\.\d+\.\d+\.\d+)(:\d+)?(#|\s|\||$)', line):
        return True
    
    # 保留特定域名
    if re.match(r'^(www|ct|cmcc)\.cf\.090227\.xyz:443#', line):
        return True
    
    # 保留其他域名（但需要确保最终能解析出IPv4）
    if re.match(r'^[\w\.-]+:\d+#', line):
        return True
    
    return False

def format_ip_line(line):
    """格式化IP行，只处理IPv4"""
    ipv4_match = re.match(r'(\d+\.\d+\.\d+\.\d+)(:\d+)?(.*)', line)
    if ipv4_match:
        ip = ipv4_match.group(1)
        port = ipv4_match.group(2) or ':443'
        rest = ipv4_match.group(3)
        return f'{ip}{port}{rest}'
    
    # 对于域名行，原样返回
    return line

def ensure_remark(line, remark):
    """确保行有备注"""
    if '#' in line:
        return line
    # 提取IPv4地址作为备注
    ipv4 = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
    if ipv4:
        tag = ipv4.group(1)
    else:
        tag = remark or '无备注'
    return f"{line}#{tag}"

def extract_ip_from_line(line):
    """从行中提取IP地址"""
    ipv4_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
    if ipv4_match:
        return ipv4_match.group(1)
    return None

def extract_port_from_line(line):
    """从行中提取端口"""
    port_match = re.search(r':(\d+)', line)
    if port_match:
        return int(port_match.group(1))
    return 443  # 默认端口

def test_tcp_connectivity(ip, port=443, timeout=3):
    """测试TCP连接延迟"""
    try:
        start_time = time.time()
        # 创建socket连接
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # 尝试连接
        result = sock.connect_ex((ip, port))
        end_time = time.time()
        sock.close()
        
        if result == 0:  # 连接成功
            delay = int((end_time - start_time) * 1000)  # 转换为毫秒
            # 确保最小延迟为1ms
            return True, max(1, delay)
        return False, None
    except Exception:
        return False, None

def test_http_connectivity(ip, port=443, timeout=3):
    """测试HTTP/HTTPS连接延迟"""
    try:
        start_time = time.time()
        
        # 根据端口选择协议
        protocol = 'https' if port == 443 else 'http'
        url = f"{protocol}://{ip}:{port}"
        
        # 发送HEAD请求（比GET更快）
        response = requests.head(
            url, 
            timeout=timeout, 
            verify=False, 
            allow_redirects=False,
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        
        end_time = time.time()
        delay = int((end_time - start_time) * 1000)  # 转换为毫秒
        
        # 任何响应都认为是成功的（包括404）
        if response.status_code:
            return True, max(1, delay)  # 确保最小延迟为1ms
        return False, None
    except requests.exceptions.Timeout:
        return False, None
    except requests.exceptions.ConnectionError:
        return False, None
    except Exception:
        return False, None

def test_ip_connectivity(ip, port=443, timeout=3, test_method='both'):
    """综合测试IP连通性"""
    
    # 先测试TCP连接（更快）
    tcp_success, tcp_delay = test_tcp_connectivity(ip, port, timeout)
    
    if not tcp_success:
        return False, None
    
    # 如果只需要TCP测试，直接返回
    if test_method == 'tcp':
        return True, tcp_delay
    
    # 再进行HTTP测试（获取更准确的延迟）
    http_success, http_delay = test_http_connectivity(ip, port, timeout)
    
    if http_success:
        # 综合两种测试的延迟，取平均值
        avg_delay = int((tcp_delay + http_delay) / 2)
        return True, avg_delay
    elif test_method == 'both':
        # 如果HTTP失败但TCP成功，返回TCP延迟
        return True, tcp_delay
    else:
        return False, None

def process_single_line(line, remark):
    """处理单行IP，包括连通性测试"""
    # 格式化和备注处理
    formatted_line = format_ip_line(line)
    formatted_line = ensure_remark(formatted_line, remark)
    
    # 提取IP和端口
    ip = extract_ip_from_line(formatted_line)
    if not ip:
        return None  # 没有IP地址，跳过
    
    port = extract_port_from_line(formatted_line)
    
    # 测试连通性（使用综合测试方法）
    is_connected, delay = test_ip_connectivity(ip, port, timeout=3, test_method='both')
    
    if is_connected and delay:
        # 移除可能已存在的延迟信息
        base_line = re.sub(r'\s*\|\s*\d+ms', '', formatted_line)
        
        # 添加新的延迟信息
        if '#' in base_line:
            base, remark_part = base_line.split('#', 1)
            return f"{base}#{remark_part} | {delay}ms"
        else:
            return f"{base_line} | {delay}ms"
    
    return None

def parse_api_content(url, remark, text):
    """解析API内容"""
    # 清理HTML标签
    text = re.sub(r'<script[\s\S]*?</script>', '', text, flags=re.I)
    text = re.sub(r'<style[\s\S]*?</style>', '', text, flags=re.I)
    text = re.sub(r'<[^>]+>', '', text)
    
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    valid_lines = []
    
    # 特殊处理 cf.090227.xyz
    if 'cf.090227.xyz' in url:
        result = [
            'www.cf.090227.xyz:443#三网自适应分流-www.cf.090227.xyz',
            'ct.090227.xyz:443#电信分流-ct.090227.xyz',
            'cmcc.090227.xyz:443#移动分流-cmcc.090227.xyz'
        ]
        for line in lines:
            m = re.match(r'(电信|移动|联通|三网)\s+([\d\.]+)\s+.*?([\d\.]+MB/s)', line)
            if m:
                net, ip, speed = m.groups()
                result.append(f'{ip}:443#{net}分流-{ip} | {speed}')
        return result
    
    # 特殊处理带速度信息的IP
    if 'ip.164746.xyz' in url and 'IP地址' in text:
        result = []
        for line in lines:
            m = re.match(r'(★?\s*([\d\.]+))\s+\d+\s+\d+\s+[\d\.]+%\s+[\d\.]+\s+([\d\.]+MB/s)', line)
            if m:
                ip = m.group(2)
                speed = m.group(3)
                result.append(f'{ip}:443#{ip} | ⬇️ {speed}')
        return result
    
    # 通用处理：只保留有效的IPv4行
    for line in lines:
        if is_valid_ip_line(line):
            valid_lines.append(line)
    
    return valid_lines

def process_api(api):
    """处理单个API"""
    api_results = []
    try:
        print(f"正在获取【{api['remark']}】...")
        resp = requests.get(api['url'], timeout=15)
        resp.encoding = resp.apparent_encoding
        
        # 解析API内容
        lines = parse_api_content(api['url'], api['remark'], resp.text)
        
        if not lines:
            print(f"【{api['remark']}】没有获取到有效IP")
            return api_results
        
        print(f"【{api['remark']}】获取到 {len(lines)} 条IP，正在进行连通性测试...")
        
        # 使用线程池并发测试连通性
        success_count = 0
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_line = {
                executor.submit(process_single_line, line, api['remark']): line 
                for line in lines
            }
            
            for future in as_completed(future_to_line):
                try:
                    result = future.result(timeout=10)
                    if result:
                        api_results.append(result)
                        success_count += 1
                        # 实时显示进度
                        if success_count % 10 == 0:
                            print(f"【{api['remark']}】已测试通过 {success_count} 条...")
                except Exception as e:
                    continue
        
        print(f"【{api['remark']}】通过连通性测试: {success_count}/{len(lines)} 条")
        
    except Exception as e:
        print(f"【{api['remark']}】获取失败: {e}")
    
    return api_results

def remove_duplicates(lines):
    """去重函数"""
    seen_ips = set()
    unique_lines = []
    
    for line in lines:
        # 提取IP地址
        ip = extract_ip_from_line(line)
        if not ip:
            continue
            
        if ip not in seen_ips:
            seen_ips.add(ip)
            unique_lines.append(line)
    
    return unique_lines

def sort_by_delay(lines):
    """按延迟排序"""
    def extract_delay(line):
        delay_match = re.search(r'(\d+)ms', line)
        if delay_match:
            return int(delay_match.group(1))
        return 9999  # 没有延迟信息的放到最后
    
    return sorted(lines, key=extract_delay)

def main():
    if not os.path.exists(API_CONFIG_FILE):
        print('api_config.json不存在')
        return
    
    with open(API_CONFIG_FILE, 'r', encoding='utf-8') as f:
        api_list = json.load(f)
    
    all_results = []
    
    # 串行处理每个API（避免请求过快被限制）
    for api in api_list:
        api_results = process_api(api)
        all_results.extend(api_results)
    
    if not all_results:
        print("没有获取到任何可用的IP")
        return
    
    # 去重
    print(f"\n去重前: {len(all_results)} 条")
    unique_results = remove_duplicates(all_results)
    print(f"去重后: {len(unique_results)} 条")
    
    # 按延迟排序
    sorted_results = sort_by_delay(unique_results)
    
    # 写入文件
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted_results))
    
    print(f"\n已完成！共 {len(sorted_results)} 条有效IP写入 {OUTPUT_FILE}")
    
    # 打印延迟统计
    delays = []
    for line in sorted_results:
        delay_match = re.search(r'(\d+)ms', line)
        if delay_match:
            delays.append(int(delay_match.group(1)))
    
    if delays:
        print(f"\n延迟统计:")
        print(f"  最小延迟: {min(delays)}ms")
        print(f"  最大延迟: {max(delays)}ms")
        print(f"  平均延迟: {sum(delays)//len(delays)}ms")
    
    # 打印前25条最快的IP
    print("\n最快的25个IP：")
    for i, line in enumerate(sorted_results[:25], 1):
        print(f"{i}. {line}")

if __name__ == '__main__':
    print("开始获取优选IP...")
    print("=" * 50)
    main()
