# app/core/utils.py - 工具函数模块
import time
import logging
from functools import wraps
from typing import Callable, Any

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('omni_soc.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


def retry_on_429(max_retries: int = 3, base_delay: float = 1.0, backoff_factor: float = 2.0):
    """
    针对API 429错误的重试装饰器

    Args:
        max_retries: 最大重试次数
        base_delay: 基础延迟时间（秒）
        backoff_factor: 指数退避因子
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            retries = 0
            delay = base_delay

            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    # 检查是否为429错误（API限流）
                    if "429" in str(e) or "Too Many Requests" in str(e):
                        retries += 1
                        if retries < max_retries:
                            logger.warning(f"API限流错误，第{retries}次重试，等待{delay}秒...")
                            time.sleep(delay)
                            delay *= backoff_factor  # 指数退避
                        else:
                            logger.error(f"API限流错误，达到最大重试次数{max_retries}")
                            raise
                    else:
                        # 其他错误直接抛出
                        logger.error(f"API调用失败: {e}")
                        raise

            return None

        return wrapper
    return decorator


def handle_llm_error(func: Callable) -> Callable:
    """
    LLM调用的通用错误处理装饰器
    """
    @wraps(func)
    def wrapper(*args, **kwargs) -> Any:
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"LLM调用异常: {type(e).__name__}: {e}")
            raise
    return wrapper


def log_node_execution(node_name: str):
    """
    节点执行的日志记录装饰器
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            logger.info(f"[{node_name}] 开始执行")
            try:
                result = func(*args, **kwargs)
                logger.info(f"[{node_name}] 执行成功")
                return result
            except Exception as e:
                logger.error(f"[{node_name}] 执行失败: {e}")
                raise
        return wrapper
    return decorator


def safe_llm_invoke(llm, prompt: str, max_retries: int = 3) -> str:
    """
    安全的LLM调用函数，带有重试机制

    Args:
        llm: LLM实例
        prompt: 提示文本
        max_retries: 最大重试次数

    Returns:
        LLM响应内容
    """
    from app.core.utils import retry_on_429

    @retry_on_429(max_retries=max_retries)
    def _invoke():
        response = llm.invoke(prompt)
        return response.content

    return _invoke()


def format_error_message(error: Exception, context: str = "") -> str:
    """
    格式化错误消息

    Args:
        error: 异常对象
        context: 上下文信息

    Returns:
        格式化的错误消息
    """
    error_type = type(error).__name__
    error_msg = str(error)
    context_prefix = f"{context}: " if context else ""
    return f"{context_prefix}{error_type}: {error_msg}"


def validate_alert_data(alert: dict) -> bool:
    """
    验证告警数据的有效性

    Args:
        alert: 告警数据字典

    Returns:
        是否有效
    """
    required_fields = ["devSourceName", "riskTag", "description"]
    for field in required_fields:
        if field not in alert or not alert[field]:
            logger.warning(f"告警数据缺少必要字段: {field}")
            return False
    return True