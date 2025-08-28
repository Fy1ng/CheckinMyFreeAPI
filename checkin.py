#!/usr/bin/env python3
"""
AnyRouter.top 自动签到脚本
"""

import asyncio
import json
import os
import sys
from datetime import datetime
from typing import List, Union

import httpx
from dotenv import load_dotenv
from playwright.async_api import async_playwright

from notify import notify

load_dotenv()


def load_accounts():
	"""从环境变量加载多账号配置"""
	accounts_str = os.getenv('ANYROUTER_ACCOUNTS')
	if not accounts_str:
		print('ERROR: ANYROUTER_ACCOUNTS environment variable not found')
		return None

	try:
		accounts_data = json.loads(accounts_str)

		# 检查是否为数组格式
		if not isinstance(accounts_data, list):
			print('ERROR: Account configuration must use array format [{}]')
			return None

		# 验证账号数据格式
		for i, account in enumerate(accounts_data):
			if not isinstance(account, dict):
				print(f'ERROR: Account {i + 1} configuration format is incorrect')
				return None
			if 'cookies' not in account or 'api_user' not in account:
				print(f'ERROR: Account {i + 1} missing required fields (cookies, api_user)')
				return None

		return accounts_data
	except Exception as e:
		print(f'ERROR: Account configuration format is incorrect: {e}')
		return None


def parse_cookies(cookies_data):
	"""解析 cookies 数据"""
	if isinstance(cookies_data, dict):
		return cookies_data

	if isinstance(cookies_data, str):
		cookies_dict = {}
		for cookie in cookies_data.split(';'):
			if '=' in cookie:
				key, value = cookie.strip().split('=', 1)
				cookies_dict[key] = value
		return cookies_dict
	return {}


def format_message(message: Union[str, List[str]], use_emoji: bool = False) -> str:
	"""格式化消息，支持 emoji 和纯文本"""
	emoji_map = {
		'success': '✅' if use_emoji else '[SUCCESS]',
		'fail': '❌' if use_emoji else '[FAILED]',
		'info': 'ℹ️' if use_emoji else '[INFO]',
		'warn': '⚠️' if use_emoji else '[WARNING]',
		'error': '💥' if use_emoji else '[ERROR]',
		'money': '💰' if use_emoji else '[BALANCE]',
		'time': '⏰' if use_emoji else '[TIME]',
		'stats': '📊' if use_emoji else '[STATS]',
		'start': '🤖' if use_emoji else '[SYSTEM]',
		'loading': '🔄' if use_emoji else '[PROCESSING]',
	}

	if isinstance(message, str):
		result = message
		for key, value in emoji_map.items():
			result = result.replace(f':{key}:', value)
		return result
	elif isinstance(message, list):
		return '\n'.join(format_message(m, use_emoji) for m in message if isinstance(m, str))
	return ''


async def get_waf_cookies_with_playwright(account_name: str):
	"""使用 Playwright 获取 WAF cookies（隐私模式）"""
	print(f'[PROCESSING] {account_name}: Starting browser to get WAF cookies...')

	async with async_playwright() as p:
		# 创建浏览器上下文（隐私模式）
		try:
			context = await p.chromium.launch_persistent_context(
				user_data_dir=None,  # 使用临时目录，相当于隐私模式
				headless=False,  # 有头模式运行
				# 如果需要指定 Chrome 路径，可以取消注释下面这行
				# executable_path="C:/Program Files/Google/Chrome/Application/chrome.exe",
				user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
				viewport={'width': 1920, 'height': 1080},
				args=[
					'--disable-blink-features=AutomationControlled',
					'--disable-dev-shm-usage',
					'--disable-web-security',
					'--disable-features=VizDisplayCompositor',
					'--no-sandbox',  # 在 CI 环境中可能需要
				],
			)
		except Exception as e:
			print(f'[FAILED] {account_name}: Failed to start headed mode, trying headless mode: {e}')
			# 如果有头模式失败，回退到无头模式
			context = await p.chromium.launch_persistent_context(
				user_data_dir=None,
				headless=True,
				user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
				viewport={'width': 1920, 'height': 1080},
				args=[
					'--disable-blink-features=AutomationControlled',
					'--disable-dev-shm-usage',
					'--disable-web-security',
					'--disable-features=VizDisplayCompositor',
					'--no-sandbox',
				],
			)

		# 创建页面
		page = await context.new_page()

		try:
			print(f'[PROCESSING] {account_name}: Step 1: Access login page to get initial cookies...')

			# 访问登录页面
			await page.goto('https://anyrouter.top/login', wait_until='networkidle')

			# 等待页面加载
			await page.wait_for_timeout(3000)

			# 获取当前 cookies
			cookies = await page.context.cookies()

			# 查找 WAF cookies
			waf_cookies = {}
			for cookie in cookies:
				if cookie['name'] in ['acw_tc', 'cdn_sec_tc', 'acw_sc__v2']:
					waf_cookies[cookie['name']] = cookie['value']

			print(f'[INFO] {account_name}: Got {len(waf_cookies)} WAF cookies after step 1')

			# 检查是否需要第二步
			if 'acw_sc__v2' not in waf_cookies:
				print(f'[PROCESSING] {account_name}: Step 2: Re-access page to get acw_sc__v2...')

				# 等待一段时间
				await page.wait_for_timeout(2000)

				# 刷新页面或重新访问
				await page.reload(wait_until='networkidle')

				# 等待页面加载
				await page.wait_for_timeout(3000)

				# 再次获取 cookies
				cookies = await page.context.cookies()

				# 更新 WAF cookies
				for cookie in cookies:
					if cookie['name'] in ['acw_tc', 'cdn_sec_tc', 'acw_sc__v2']:
						waf_cookies[cookie['name']] = cookie['value']

				print(f'[INFO] {account_name}: Got {len(waf_cookies)} WAF cookies after step 2')

			# 验证是否获取到所有必要的 cookies
			required_cookies = ['acw_tc', 'cdn_sec_tc', 'acw_sc__v2']
			missing_cookies = [c for c in required_cookies if c not in waf_cookies]

			if missing_cookies:
				print(f'[FAILED] {account_name}: Missing WAF cookies: {missing_cookies}')
				await context.close()
				return None

			print(f'[SUCCESS] {account_name}: Successfully got all WAF cookies')

			# 关闭浏览器上下文
			await context.close()

			return waf_cookies

		except Exception as e:
			print(f'[FAILED] {account_name}: Error occurred while getting WAF cookies: {e}')
			await context.close()
			return None


def get_user_info(client, headers):
	"""获取用户信息"""
	try:
		response = client.get('https://anyrouter.top/api/user/self', headers=headers, timeout=30)

		if response.status_code == 200:
			data = response.json()
			if data.get('success'):
				user_data = data.get('data', {})
				quota = round(user_data.get('quota', 0) / 500000, 2)
				used_quota = round(user_data.get('used_quota', 0) / 500000, 2)
				return f':money: Current balance: ${quota}, Used: ${used_quota}'
	except Exception as e:
		return f':fail: Failed to get user info: {str(e)[:50]}...'
	return None


async def check_in_account(account_info, account_index):
	"""为单个账号执行签到操作"""
	account_name = f'Account {account_index + 1}'
	print(f'\n[PROCESSING] Starting to process {account_name}')

	# 解析账号配置
	cookies_data = account_info.get('cookies', {})
	api_user = account_info.get('api_user', '')

	if not api_user:
		print(f'[FAILED] {account_name}: API user identifier not found')
		return False, None

	# 解析用户 cookies
	user_cookies = parse_cookies(cookies_data)
	if not user_cookies:
		print(f'[FAILED] {account_name}: Invalid configuration format')
		return False, None

	# 步骤1：获取 WAF cookies
	waf_cookies = await get_waf_cookies_with_playwright(account_name)
	if not waf_cookies:
		print(f'[FAILED] {account_name}: Unable to get WAF cookies')
		return False, None

	# 步骤2：使用 httpx 进行 API 请求
	client = httpx.Client(http2=True, timeout=30.0)

	try:
		# 合并 WAF cookies 和用户 cookies
		all_cookies = {**waf_cookies, **user_cookies}
		client.cookies.update(all_cookies)

		# 设置请求头
		headers = {
			'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36',
			'Accept': 'application/json, text/plain, */*',
			'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
			'Accept-Encoding': 'gzip, deflate, br, zstd',
			'Referer': 'https://anyrouter.top/console',
			'Origin': 'https://anyrouter.top',
			'Connection': 'keep-alive',
			'Sec-Fetch-Dest': 'empty',
			'Sec-Fetch-Mode': 'cors',
			'Sec-Fetch-Site': 'same-origin',
			'new-api-user': api_user,
		}

		user_info_text = None

		# 获取用户信息
		user_info = get_user_info(client, headers)
		if user_info:
			print(user_info)
			user_info_text = user_info

		# 执行签到操作
		print(f'[NETWORK] {account_name}: Executing check-in')

		# 更新签到请求头
		checkin_headers = headers.copy()
		checkin_headers.update({'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'})

		response = client.post('https://anyrouter.top/api/user/sign_in', headers=checkin_headers, timeout=30)

		print(f'[RESPONSE] {account_name}: Response status code {response.status_code}')

		if response.status_code == 200:
			try:
				result = response.json()
				if result.get('ret') == 1 or result.get('code') == 0 or result.get('success'):
					print(f'[SUCCESS] {account_name}: Check-in successful!')
					return True, user_info_text
				else:
					error_msg = result.get('msg', result.get('message', 'Unknown error'))
					print(f'[FAILED] {account_name}: Check-in failed - {error_msg}')
					return False, user_info_text
			except json.JSONDecodeError:
				# 如果不是 JSON 响应，检查是否包含成功标识
				if 'success' in response.text.lower():
					print(f'[SUCCESS] {account_name}: Check-in successful!')
					return True, user_info_text
				else:
					print(f'[FAILED] {account_name}: Check-in failed - Invalid response format')
					return False, user_info_text
		else:
			print(f'[FAILED] {account_name}: Check-in failed - HTTP {response.status_code}')
			return False, user_info_text

	except Exception as e:
		print(f'[FAILED] {account_name}: Error occurred during check-in process - {str(e)[:50]}...')
		return False, user_info_text
	finally:
		# 关闭 HTTP 客户端
		client.close()


async def main():
	"""主函数"""
	print('[SYSTEM] AnyRouter.top multi-account auto check-in script started (using Playwright)')
	print(f'[TIME] Execution time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')

	# 加载账号配置
	accounts = load_accounts()
	if not accounts:
		print('[FAILED] Unable to load account configuration, program exits')
		sys.exit(1)

	print(f'[INFO] Found {len(accounts)} account configurations')

	# 为每个账号执行签到
	success_count = 0
	total_count = len(accounts)
	notification_content = []

	for i, account in enumerate(accounts):
		try:
			success, user_info = await check_in_account(account, i)
			if success:
				success_count += 1
			# 收集通知内容
			status = ':success:' if success else ':fail:'
			account_result = f'{status} Account {i + 1}'
			if user_info:
				account_result += f'\n{user_info}'
			notification_content.append(account_result)
		except Exception as e:
			print(f'[FAILED] Account {i + 1} processing exception: {e}')
			notification_content.append(f':fail: Account {i + 1} exception: {str(e)[:50]}...')

	# 构建通知内容
	summary = [
		':stats: Check-in result statistics:',
		f':success: Success: {success_count}/{total_count}',
		f':fail: Failed: {total_count - success_count}/{total_count}',
	]

	if success_count == total_count:
		summary.append(':success: All accounts check-in successful!')
	elif success_count > 0:
		summary.append(':warn: Some accounts check-in successful')
	else:
		summary.append(':error: All accounts check-in failed')

	# 生成通知内容
	time_info = f':time: Execution time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'

	# 控制台输出
	console_content = '\n'.join(
		[
			format_message(time_info, use_emoji=False),
			format_message(notification_content, use_emoji=False),
			format_message(summary, use_emoji=False),
		]
	)

	# 通知内容
	notify_content = '\n\n'.join(
		[format_message(time_info), format_message(notification_content), format_message(summary)]
	)

	# 输出到控制台
	print('\n' + console_content)

	# 发送通知
	notify.push_message('AnyRouter Check-in Results', notify_content, msg_type='text')

	# 设置退出码
	sys.exit(0 if success_count > 0 else 1)


def run_main():
	"""运行主函数的包装函数"""
	try:
		asyncio.run(main())
	except KeyboardInterrupt:
		print('\n[WARNING] Program interrupted by user')
		sys.exit(1)
	except Exception as e:
		print(f'\n[FAILED] Error occurred during program execution: {e}')
		sys.exit(1)


if __name__ == '__main__':
	run_main()
