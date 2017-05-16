# SDN Firewall
implementation of SDN firewall on POX controller

## l2_firewall_Mac.py
* Added drop/forward desicions to the learning switch module shippes with the POX controller **l2_learning.py:** .
* Now the controller doesnt install flow-enteries into the  switch unless there is a forward desicision that this mac adress can forward packets according to the firewall table.   
* For simplicity 2 rules where added on switch 1, were any packet coming from ***mac_adress_1*** and ***mac_adress_1*** is forwarded, other than those 2 mac adresses any packets will be droped and no flow-enteries will be installed on the switch.   

## l2_firewall_IP.py
* Here the flow tables on all switches is added at the begining of the programm with the dicision action DROP.
* The learning switch is then proceeed the same as before but hen a packet comes which already have a preinstalled flow table on that switch with the action DROP it will be droped.
* For simplicity 1 rules was added, where any traffic between ***ip_adress_1*** and ***ip_adress_1*** is Blocked.
