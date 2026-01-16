#!/usr/bin/env python3
"""
文件操作工具模块

提供扫描结果的统一保存功能，支持生成带时间戳的历史文件和固定名称的 latest 文件。
"""

import json
import os
from datetime import datetime
from typing import Any, Optional, Tuple


def get_timestamped_filename(prefix: str) -> str:
    """
    生成带时间戳的文件名

    Args:
        prefix: 文件名前缀（如 'waf_config', 'alb_config'）

    Returns:
        带时间戳的文件名，格式: {prefix}_YYYYMMDD_HHMMSS.json

    Example:
        >>> get_timestamped_filename('waf_config')
        'waf_config_20260116_143025.json'
    """
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return f'{prefix}_{timestamp}.json'


def get_latest_filename(prefix: str) -> str:
    """
    生成固定的 latest 文件名

    Args:
        prefix: 文件名前缀（如 'waf_config', 'alb_config'）

    Returns:
        固定的 latest 文件名，格式: {prefix}_latest.json

    Example:
        >>> get_latest_filename('waf_config')
        'waf_config_latest.json'
    """
    return f'{prefix}_latest.json'


def save_scan_results(
    data: Any,
    prefix: str,
    output_file: Optional[str] = None,
    save_latest: bool = True,
    verbose: bool = True
) -> Tuple[str, Optional[str]]:
    """
    保存扫描结果到 JSON 文件，支持双文件输出

    Args:
        data: 要保存的数据（通常是字典或列表）
        prefix: 文件名前缀（如 'waf_config', 'alb_config', 'route53_config'）
        output_file: 主输出文件名（可选）。如果为 None，自动生成带时间戳的文件名
        save_latest: 是否同时保存固定名称的 latest 文件（默认 True）
        verbose: 是否显示详细输出信息（默认 True）

    Returns:
        元组 (主文件名, latest 文件名或None)

    Raises:
        Exception: 文件保存失败时抛出异常

    Example:
        >>> results = [{'profile': 'test', 'data': 'value'}]
        >>> main_file, latest_file = save_scan_results(
        ...     results,
        ...     'waf_config',
        ...     save_latest=True
        ... )
        >>> print(main_file)
        'waf_config_20260116_143025.json'
        >>> print(latest_file)
        'waf_config_latest.json'
    """
    # 生成主文件名（如果未指定）
    if not output_file:
        output_file = get_timestamped_filename(prefix)

    latest_file = None

    try:
        # 保存主文件（带时间戳）
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)

        if verbose:
            print(f"\n{'='*80}")
            print(f"✓ 结果已保存到: {output_file}")

        # 保存 latest 文件（固定名称）
        if save_latest:
            latest_file = get_latest_filename(prefix)
            with open(latest_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False, default=str)

            if verbose:
                print(f"✓ Latest 文件已保存到: {latest_file}")
                print(f"\n⚠️  注意: {latest_file} 会在下次扫描时被覆盖")
                print(f"   如需保留历史记录，请使用带时间戳的文件: {output_file}")

        if verbose:
            print(f"{'='*80}")

        return output_file, latest_file

    except Exception as e:
        error_msg = f"✗ 保存结果失败: {str(e)}"
        if verbose:
            print(f"\n{error_msg}")
        raise Exception(error_msg)


def check_latest_files_exist(prefixes: list) -> dict:
    """
    检查指定前缀的 latest 文件是否存在

    Args:
        prefixes: 文件名前缀列表（如 ['waf_config', 'alb_config', 'route53_config']）

    Returns:
        字典，键为前缀，值为布尔值表示文件是否存在

    Example:
        >>> result = check_latest_files_exist(['waf_config', 'alb_config'])
        >>> print(result)
        {'waf_config': True, 'alb_config': False}
    """
    result = {}
    for prefix in prefixes:
        latest_file = get_latest_filename(prefix)
        result[prefix] = os.path.exists(latest_file)
    return result


def get_latest_file_paths(prefixes: list) -> dict:
    """
    获取指定前缀的 latest 文件路径

    Args:
        prefixes: 文件名前缀列表

    Returns:
        字典，键为前缀，值为 latest 文件的绝对路径

    Example:
        >>> paths = get_latest_file_paths(['waf_config', 'alb_config'])
        >>> print(paths['waf_config'])
        '/path/to/waf_config_latest.json'
    """
    result = {}
    for prefix in prefixes:
        latest_file = get_latest_filename(prefix)
        result[prefix] = os.path.abspath(latest_file)
    return result


if __name__ == '__main__':
    # 简单测试
    print("Testing file_utils module...")

    # 测试文件名生成
    print(f"\nTimestamped filename: {get_timestamped_filename('test_config')}")
    print(f"Latest filename: {get_latest_filename('test_config')}")

    # 测试保存功能
    test_data = {'test': 'data', 'timestamp': datetime.now()}
    try:
        main_file, latest_file = save_scan_results(
            test_data,
            'test_config',
            save_latest=True,
            verbose=True
        )
        print(f"\n保存成功:")
        print(f"  主文件: {main_file}")
        print(f"  Latest 文件: {latest_file}")

        # 清理测试文件
        if os.path.exists(main_file):
            os.remove(main_file)
        if latest_file and os.path.exists(latest_file):
            os.remove(latest_file)
        print("\n测试文件已清理")

    except Exception as e:
        print(f"\n测试失败: {e}")

    print("\n✓ 模块测试完成")
