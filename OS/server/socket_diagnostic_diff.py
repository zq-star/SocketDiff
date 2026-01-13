import json
import os
from datetime import datetime
import threading

class SocketDiagnosticDiff:
    def __init__(self, diff_dir, output_file_prefix="diffs"):
        self.last_diagnostics = None
        self.lock = threading.Lock()
        self.diff_counter = 0
        self.diff_dir = diff_dir

        # 确保目录存在
        os.makedirs(diff_dir, exist_ok=True)

        # 生成时间戳文件名
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.diff_file = os.path.join(diff_dir, f"{output_file_prefix}_{timestamp}.json")

        # 初始化差异文件
        if not os.path.exists(self.diff_file):
            with open(self.diff_file, 'w') as f:
                json.dump({"diffs": []}, f, indent=2)

    def compare_and_save(self, current_stats1, current_stats2, tag, trigger_info=None):
        """对比并保存差异到JSON文件"""
        diff_stats = {}
        with self.lock:
            if self.last_diagnostics is not None:
                for key in current_stats1:
                    if key not in self.last_diagnostics or current_stats1[key] != self.last_diagnostics[key]:
                        if key == 'send_ip_id':
                            old_value = self.last_diagnostics.get(key, 0)
                            new_value = current_stats1[key]
                            # 计算ip_id的差值
                            ip_id_diff = abs(new_value - old_value)
                        
                            # 只有当差值大于100时才认为有差异
                            if ip_id_diff < 100:
                                diff_stats[key] = {
                                    'old_value': old_value,
                                    'new_value': new_value
                                }
                        elif key == 'rcv_ip_id':
                            pass
                        else:
                            diff_stats[key] = {
                                'old_value': self.last_diagnostics.get(key, 'N/A'),
                                'new_value': current_stats1[key]
                            }
            
            self.last_diagnostics = current_stats2.copy()
        
        if not diff_stats:
            return None
        
        self.diff_counter += 1
        
        # 构建差异记录
        diff_record = {
            'diff_number': self.diff_counter,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
            'connection_tag': tag,
            'trigger_info': trigger_info or {},
            'differences': diff_stats,
            'full_stats': current_stats1
        }
        
        # 追加记录到文件
        try:
            with open(self.diff_file, 'r+') as f:
                data = json.load(f)
                data["diffs"].append(diff_record)
                f.seek(0)
                json.dump(data, f, ensure_ascii=False, indent=2)
            return self.diff_file
        except Exception as e:
            print(f"[diag] 写入差异文件失败: {e}")
            return None

    def get_diff_file_path(self):
        """获取当前差异文件的完整路径"""
        return self.diff_file