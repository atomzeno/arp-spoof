# arp-spoof

sudo qmake arp-spoof

sudo make

sudo ./arp-spoof <interface> [sender ip address1] [target ip address1] [sender ip address2] [target ip address2] ...

로 실행시킬 수 있습니다.



sender가 attacker에게 보낸 ip 패킷과,

attacker가 target에게 보낼 ip 패킷을 다 출력창에서 볼 수 있도록 구현하였습니다.

sender가 attacker에게 보낸 ip 패킷의 arp 헤더에서 source mac address가 sender의 mac address와 같아야 한다는 조건을 넣었습니다.



3초마다 모든 (ith sender, ith target) 쌍에 대해서 ith sender가 ith target의 mac 주소를 attacker의 것으로 알게끔 구현하였고,

i번째 sender가 i번째 target의 mac address가 무엇인지 질의하는 arp request 에 대한 arp reply도 보내지도록 하였습니다.




마지막으로, 프로그램 종료시에는 ctrl + c를 누르시면,

모든 (ith sender, ith target) 쌍에 대해서 sender의 arp table에서 잘못된 target의 mac address를 

원래대로 복구할 수 있는 arp reply를 보내도록 하였습니다.

-10월 26일
