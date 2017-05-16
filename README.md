# SDN Firewall
implementation of SDN firewall on POX controller

## l2_firewall.py
* Added drop/forward desicions with the learning switch **l2_learning.py:** now the controller doesnt install flow-enteries into the  switch unless there is a forward desicision that this mac adress can forward packets.   
* For simplicity 2 rules where added on switch 1 where any packet coming from ***mac_adress_1*** and ***mac_adress_1*** is forwarded, other than those 2 mac adresses any packets will be droped and no flow-enteries will be installed on the switch   
* In this algorithm we add the **mac_adress** and **number of switch** which will be allowed to send recieve packets via this switch
