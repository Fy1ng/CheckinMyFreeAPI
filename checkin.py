#!/usr/bin/env python3
"""
AnyRouter.top 自动签到脚本
"""

import os
import sys
import requests
from datetime import datetime
import json
from typing import Union, List, Optional
from notify import notify


def load_accounts():
    """从环境变量加载多账号配置"""
    accounts_str = os.getenv("ANYROUTER_ACCOUNTS")
    if not accounts_str:
        print("错误: 未找到 ANYROUTER_ACCOUNTS 环境变量")
        return None

    try:
        accounts_data = json.loads(accounts_str)

        # 检查是否为数组格式
        if not isinstance(accounts_data, list):
            print("错误: 账号配置必须使用数组格式 [{}]")
            return None

        # 验证账号数据格式
        for i, account in enumerate(accounts_data):
            if not isinstance(account, dict):
                print(f"错误: 账号 {i+1} 配置格式不正确")
                return None
            if "cookies" not in account or "api_user" not in account:
                print(f"错误: 账号 {i+1} 缺少必要字段 (cookies, api_user)")
                return None

        return accounts_data
    except Exception as e:
        print(f"错误: 账号配置格式不正确: {e}")
        return None


def parse_cookies(cookies_data):
    """解析 cookies 数据"""
    if isinstance(cookies_data, dict):
        return cookies_data

    if isinstance(cookies_data, str):
        cookies_dict = {}
        for cookie in cookies_data.split(";"):
            if "=" in cookie:
                key, value = cookie.strip().split("=", 1)
                cookies_dict[key] = value
        return cookies_dict
    return {}


def format_message(message: Union[str, List[str]], use_emoji: bool = True) -> str:
    """格式化消息，支持 emoji 和纯文本"""
    emoji_map = {
        "success": "✅" if use_emoji else "[成功]",
        "fail": "❌" if use_emoji else "[失败]",
        "info": "ℹ️" if use_emoji else "[信息]",
        "warn": "⚠️" if use_emoji else "[警告]",
        "error": "💥" if use_emoji else "[错误]",
        "money": "💰" if use_emoji else "[余额]",
        "time": "⏰" if use_emoji else "[时间]",
        "stats": "📊" if use_emoji else "[统计]",
        "start": "🤖" if use_emoji else "[系统]",
        "loading": "🔄" if use_emoji else "[处理]"
    }
    
    if isinstance(message, str):
        result = message
        for key, value in emoji_map.items():
            result = result.replace(f":{key}:", value)
        return result
    elif isinstance(message, list):
        return "\n".join(format_message(m, use_emoji) for m in message if isinstance(m, str))
    return ""


def get_user_info(session, headers):
    """获取用户信息"""
    try:
        response = session.get(
            "https://anyrouter.top/api/user/self",
            headers=headers,
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get("success"):
                user_data = data.get("data", {})
                quota = round(user_data.get("quota", 0) / 50000, 2)
                used_quota = round(user_data.get("used_quota", 0) / 50000, 2)
                return f":money: 当前余额: {quota}GB, 已消耗: {used_quota}GB"
    except Exception as e:
        return f":fail: 获取用户信息失败: {str(e)[:50]}..."
    return None


def check_in_account(account_info, account_index):
    """为单个账号执行签到操作"""
    account_name = f"账号 {account_index + 1}"
    print(f"\n🔄 开始处理 {account_name}")

    # 解析账号配置
    cookies_data = account_info.get("cookies", {})
    api_user = account_info.get("api_user", "")

    if not api_user:
        print(f"❌ {account_name}: 未找到 API 用户标识")
        return False, None

    # 解析 cookies
    cookies = parse_cookies(cookies_data)
    if not cookies:
        print(f"❌ {account_name}: 配置格式不正确")
        return False, None

    # 创建 session
    session = requests.Session()
    session.cookies.update(cookies)

    # 设置请求头
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "Referer": "https://anyrouter.top/console",
        "Origin": "https://anyrouter.top",
        "Connection": "keep-alive",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "new-api-user": api_user,
    }

    user_info_text = None
    try:
        # 获取用户信息
        user_info = get_user_info(session, headers)
        if user_info:
            print(user_info)
            user_info_text = user_info

        # 执行签到操作
        checkin_url = "https://anyrouter.top/api/user/sign_in"

        print(f"🔗 {account_name}: 正在执行签到")
        response = session.post(checkin_url, headers=headers, timeout=30)
        print(f"📡 {account_name}: 响应状态码 {response.status_code}")

        if response.status_code == 200:
            try:
                result = response.json()
                if (
                    result.get("ret") == 1
                    or result.get("code") == 0
                    or result.get("success")
                ):
                    print(f"✅ {account_name}: 签到成功!")
                    return True, user_info_text
                else:
                    error_msg = result.get("msg", result.get("message", "未知错误"))
                    print(f"❌ {account_name}: 签到失败 - {error_msg}")
                    return False, user_info_text
            except json.JSONDecodeError:
                # 如果不是 JSON 响应，检查是否包含成功标识
                if "成功" in response.text or "success" in response.text.lower():
                    print(f"✅ {account_name}: 签到成功!")
                    return True, user_info_text
                else:
                    print(f"❌ {account_name}: 签到失败 - 响应格式不正确")
                    return False, user_info_text
        else:
            print(f"❌ {account_name}: 签到失败 - HTTP {response.status_code}")
            return False, user_info_text

    except requests.RequestException as e:
        print(f"❌ {account_name}: 请求失败 - {str(e)[:50]}...")
        return False, user_info_text
    except Exception as e:
        print(f"❌ {account_name}: 签到过程中发生错误 - {str(e)[:50]}...")
        return False, user_info_text


def main():
    """主函数"""
    print(f"🤖 AnyRouter.top 多账号自动签到脚本启动")
    print(f"📅 执行时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # 加载账号配置
    accounts = load_accounts()
    if not accounts:
        print("❌ 无法加载账号配置，程序退出")
        sys.exit(1)

    print(f"📋 找到 {len(accounts)} 个账号配置")

    # 为每个账号执行签到
    success_count = 0
    total_count = len(accounts)
    notification_content = []

    for i, account in enumerate(accounts):
        try:
            success, user_info = check_in_account(account, i)
            if success:
                success_count += 1
            # 收集通知内容
            status = ":success:" if success else ":fail:"
            account_result = f"{status} 账号 {i+1}"
            if user_info:
                account_result += f"\n{user_info}"
            notification_content.append(account_result)
        except Exception as e:
            print(f"❌ 账号 {i+1} 处理异常: {e}")
            notification_content.append(f":fail: 账号 {i+1} 异常: {str(e)[:50]}...")

    # 构建通知内容
    summary = [
        ":stats: 签到结果统计:",
        f":success: 成功: {success_count}/{total_count}",
        f":fail: 失败: {total_count - success_count}/{total_count}"
    ]

    if success_count == total_count:
        summary.append(":success: 所有账号签到成功!")
    elif success_count > 0:
        summary.append(":warn: 部分账号签到成功")
    else:
        summary.append(":error: 所有账号签到失败")

    # 生成通知内容
    time_info = f":time: 执行时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    
    # 控制台输出
    console_content = "\n".join([
        format_message(time_info, use_emoji=False),
        format_message(notification_content, use_emoji=False),
        format_message(summary, use_emoji=False)
    ])
    
    # 通知内容
    notify_content = "\n\n".join([
        format_message(time_info),
        format_message(notification_content),
        format_message(summary)
    ])

    # 输出到控制台
    print("\n" + console_content)
    
    # 发送通知
    notify.push_message("AnyRouter 签到结果", notify_content, msg_type='text')

    # 设置退出码
    sys.exit(0 if success_count > 0 else 1)


if __name__ == "__main__":
    main()
