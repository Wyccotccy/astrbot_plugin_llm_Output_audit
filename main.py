from astrbot.api.event import filter, AstrMessageEvent
from astrbot.api.star import Context, Star, register
from astrbot.api.provider import ProviderRequest, LLMResponse
from astrbot.api import logger, AstrBotConfig
import re
from typing import Tuple, Optional


@register(
    "content_safety_check",
    "AstrBotCommunity",
    "LLM输入输出内容合规检测插件，支持正则违禁词、大模型审核、黑白名单、自定义合规表达、动态指令添加",
    "1.1.0",
    "https://github.com/Soulter/astrbot_plugin_content_safety"
)
class ContentSafetyPlugin(Star):
    def __init__(self, context: Context, config: AstrBotConfig):
        super().__init__(context)
        self.context = context
        self.config = config
        
        # 解析合规表达配置 格式：词汇~原因
        self.allowed_expressions = {}
        allowed_expr_list = self.config.get("allowed_expressions", [])
        for expr in allowed_expr_list:
            if "~" not in expr:
                logger.error(f"合规表达 `{expr}` 格式错误，缺少「~」分隔符，已自动跳过")
                continue
            word, reason = expr.split("~", 1)
            word = word.strip()
            reason = reason.strip()
            if not word or not reason:
                logger.error(f"合规表达 `{expr}` 格式错误，词汇或原因不能为空，已自动跳过")
                continue
            self.allowed_expressions[word] = reason

        # 预编译正则表达式，提升检测性能
        # 1. 用户配置的白名单正则
        user_allowed_patterns = self._compile_patterns(self.config.get("allowed_regex", []))
        # 2. 合规表达的白名单正则（单词边界匹配，避免部分匹配违规内容）
        expr_allowed_patterns = []
        for word in self.allowed_expressions.keys():
            try:
                expr_allowed_patterns.append(re.compile(rf"\b{re.escape(word)}\b", re.IGNORECASE))
            except re.error as e:
                logger.error(f"合规词汇 `{word}` 正则编译失败: {str(e)}，已自动跳过")
        # 合并白名单
        self.allowed_patterns = user_allowed_patterns + expr_allowed_patterns
        
        # 违禁词正则
        self.banned_patterns = self._compile_patterns(self.config.get("banned_regex", []))
        
        logger.info("内容合规检测插件 v1.1.0 加载完成")

    def _compile_patterns(self, pattern_list: list) -> list:
        """预编译正则表达式，自动捕获并跳过语法错误的规则"""
        compiled = []
        for pattern in pattern_list:
            try:
                compiled.append(re.compile(pattern, re.IGNORECASE))
            except re.error as e:
                logger.error(f"正则规则 `{pattern}` 编译失败: {str(e)}，已自动跳过")
        return compiled

    def _regex_check(self, content: str) -> Tuple[bool, Optional[str]]:
        """
        正则黑白名单检测
        返回值: (是否触发拦截, 拦截原因)
        """
        # 白名单优先级最高，匹配到直接放行
        for pattern in self.allowed_patterns:
            if pattern.search(content):
                return False, None
        # 违禁词检测
        for pattern in self.banned_patterns:
            match = pattern.search(content)
            if match:
                return True, f"匹配违禁规则: `{pattern.pattern}`"
        return False, None

    async def _llm_check(self, content: str, provider_id: str) -> Tuple[bool, Optional[str]]:
        """
        大模型合规检测，自动注入合规表达说明
        返回值: (是否触发拦截, 拦截原因)
        """
        # 获取检测用的大模型实例
        if not provider_id:
            provider = self.context.get_using_provider()
        else:
            provider = self.context.get_provider_by_id(provider_id)
        
        if not provider:
            logger.error("未找到可用的大模型提供商，跳过本次大模型检测")
            return False, None
        
        # 基础检测提示词
        base_prompt = self.config.get("check_prompt", """
你是专业的内容合规审核员，需严格检查内容是否符合中国法律法规与公序良俗。
不合规内容包括但不限于：色情低俗、暴力恐怖、诈骗诱导、违法违规、政治敏感、人身攻击、歧视辱骂等。
必须严格按照以下格式回复，禁止额外内容：
1. 内容合规：仅回复「合规」
2. 内容不合规：仅回复「不合规|违规类型」，例如「不合规|色情低俗」
        """.strip())

        # 注入合规表达说明，告知模型这些内容绝对合规
        if self.allowed_expressions:
            allowed_text = "\n\n以下表达是合规且被允许的，即使内容看起来有歧义，也绝对不能拦截，需判定为合规：\n"
            for word, reason in self.allowed_expressions.items():
                allowed_text += f"- {word}：{reason}\n"
            base_prompt += allowed_text

        try:
            resp = await provider.text_chat(
                prompt=f"待检测内容：{content}",
                system_prompt=base_prompt
            )
            result = resp.completion_text.strip()
            if result.startswith("不合规"):
                reason = result.split("|", 1)[1] if "|" in result else "内容违反合规要求"
                return True, reason
            elif result == "合规":
                return False, None
            else:
                logger.warning(f"大模型检测返回异常结果: {result}，本次检测视为合规")
                return False, None
        except Exception as e:
            logger.error(f"大模型检测调用失败: {str(e)}，跳过本次检测")
            return False, None

    async def _check_content(self, content: str, event: AstrMessageEvent, is_input: bool) -> Tuple[bool, Optional[str]]:
        """
        统一检测入口，整合正则和大模型检测
        返回值: (是否拦截, 拦截原因)
        """
        # 跳过忽略列表内的会话
        ignore_sessions = self.config.get("ignore_sessions", [])
        current_session = event.unified_msg_origin
        if current_session in ignore_sessions:
            logger.debug(f"会话 {current_session} 在忽略列表，跳过检测")
            return False, None
        
        # 第一步：正则检测
        regex_block, regex_reason = self._regex_check(content)
        if regex_block:
            logger.warning(f"正则拦截触发 | {regex_reason} | 内容摘要: {content[:100]}...")
            return True, regex_reason
        
        # 第二步：大模型检测
        if is_input:
            enable_llm = self.config.get("enable_input_check", False)
            provider_id = self.config.get("input_check_provider", "")
        else:
            enable_llm = True
            provider_id = self.config.get("output_check_provider", "")
        
        if enable_llm:
            llm_block, llm_reason = await self._llm_check(content, provider_id)
            if llm_block:
                logger.warning(f"大模型拦截触发 | {llm_reason} | 内容摘要: {content[:100]}...")
                return True, llm_reason
        
        return False, None

    # ========== 管理员指令：添加合规表达 ==========
    @filter.permission_type(filter.PermissionType.ADMIN)
    @filter.command("加合规", alias={"添加合规", "新增合规"})
    async def add_allowed_expression(self, event: AstrMessageEvent, word: str, *, reason: str):
        """
        添加合规表达，仅管理员可用
        格式：加合规 词汇 合规原因
        示例：加合规 我去 表达惊讶的日常语气词
        """
        # 去除首尾空格
        word = word.strip()
        reason = reason.strip()
        
        # 参数校验
        if not word:
            yield event.plain_result("❌ 词汇不能为空，请输入正确格式：\n加合规 词汇 合规原因")
            return
        if not reason:
            yield event.plain_result("❌ 合规原因不能为空，请输入正确格式：\n加合规 词汇 合规原因")
            return
        if "~" in word or "~" in reason:
            yield event.plain_result("❌ 词汇和原因中不能包含分隔符「~」，请修改后重试")
            return
        
        # 检查重复
        if word in self.allowed_expressions:
            yield event.plain_result(f"⚠️ 词汇「{word}」已在合规表达列表中，无需重复添加")
            return
        
        # 拼接配置格式
        expr_str = f"{word}~{reason}"
        
        # 更新配置文件
        current_expr_list = self.config.get("allowed_expressions", [])
        current_expr_list.append(expr_str)
        self.config.set("allowed_expressions", current_expr_list)
        
        # 更新内存中的合规表达字典
        self.allowed_expressions[word] = reason
        
        # 新增白名单正则，实时生效
        try:
            new_pattern = re.compile(rf"\b{re.escape(word)}\b", re.IGNORECASE)
            self.allowed_patterns.append(new_pattern)
        except re.error as e:
            self.config.save_config()
            yield event.plain_result(f"⚠️ 词汇「{word}」添加成功，但正则编译失败：{str(e)}\n该词汇仅对大模型检测生效，正则检测不生效")
            return
        
        # 保存配置到文件
        self.config.save_config()
        
        # 返回成功结果
        yield event.plain_result(f"✅ 合规表达添加成功！\n词汇：{word}\n合规原因：{reason}\n已实时生效，无需重启插件")

    # ========== 核心检测钩子 ==========
    @filter.on_llm_request()
    async def handle_input_check(self, event: AstrMessageEvent, req: ProviderRequest):
        """LLM请求前钩子：用户输入内容检测"""
        if not self.config.get("enable_input_check", False):
            return
        content = req.prompt
        if not content:
            return
        
        is_blocked, reason = await self._check_content(content, event, is_input=True)
        if is_blocked:
            event.stop_event()
            block_msg = self.config.get("blocked_message", "您的输入内容不合规，已被拦截。")
            await event.send(event.plain_result(block_msg))

    @filter.on_llm_response()
    async def handle_output_check(self, event: AstrMessageEvent, resp: LLMResponse):
        """LLM响应后钩子：模型输出内容检测"""
        content = resp.completion_text
        if not content:
            return
        
        is_blocked, reason = await self._check_content(content, event, is_input=False)
        if is_blocked:
            block_msg = self.config.get("blocked_message", "该回复内容不合规，已被拦截。")
            resp.completion_text = block_msg

    async def terminate(self):
        """插件卸载/重载时的资源清理"""
        logger.info("内容合规检测插件已卸载，资源已清理")
