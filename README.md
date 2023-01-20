# deauth attack with python

### 1. 개요

- 해당 코드는 Monitor mode의 무선랜 인터페이스에서 인증 및 연결해제 패킷을 송신하는 도구로, 파이썬 기반으로 작성되었습니다.
- 의존 모듈 : sys, socket, binascii
- 사용법
    
    입력되는 무선랜 인터페이스가 반드시 Monitor mode여야 정상적으로 Sniffing이 가능합니다.
    
    ```python
    sudo python deauth-attack.py <interface> <ap mac> [<station mac> [-auth]]
    ```
    

### 2. 유의사항

- 본 파이썬 코드는 별도의 다중 프로세스(또는 스레드) 기반 동작을 진행하지 않기 때문에 실제 연결이 끊어지는 시간은 길어질 수 있습니다!
