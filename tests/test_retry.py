import pytest  
import requests  
from unittest.mock import Mock, patch  
from src.retry import retry_with_backoff  

@pytest.mark.unit  
class TestRetryDecorator:  
    def test_success_on_first_attempt(self):  
        @retry_with_backoff(max_attempts=3)  
        def success_func():  
            return "success"  
          
        assert success_func() == "success"  
      
    def test_retry_then_success(self):  
        mock_func = Mock(side_effect=[Exception("fail"), "success"])  
          
        @retry_with_backoff(max_attempts=3, initial_delay=0.01)  
        def test_func():  
            return mock_func()  
          
        with patch('time.sleep'):  # Skip sleep in tests  
            assert test_func() == "success"  
            assert mock_func.call_count == 2  
      
    def test_max_attempts_reached(self):  
        @retry_with_backoff(max_attempts=2, initial_delay=0.01)  
        def always_fail():  
            raise Exception("always fails")  
          
        with patch('time.sleep'):  
            with pytest.raises(Exception, match="always fails"):  
                always_fail()