import time  
import random  
from functools import wraps  
from typing import Callable, Type, Tuple  
  
def retry_with_backoff(  
    max_attempts: int = 3,  
    initial_delay: float = 1.0,  
    max_delay: float = 10.0,  
    backoff_factor: float = 2.0,  
    exceptions: Tuple[Type[Exception], ...] = (Exception,)  
):  
    def decorator(func: Callable):  
        @wraps(func)  
        def wrapper(*args, **kwargs):  
            delay = initial_delay  
            last_exception = None  
  
            for attempt in range(max_attempts):  
                try:  
                    return func(*args, **kwargs)  
                except exceptions as e:  
                    last_exception = e  
                    if attempt == max_attempts - 1:  
                        break  
  
                    jitter = random.uniform(0.1, 0.3) * delay  
                    time.sleep(min(delay + jitter, max_delay))  
                    delay *= backoff_factor  
  
            raise last_exception  
        return wrapper  
    return decorator