# SDN Firewall
implementation of SDN firewall on POX controller

## l2_firewall.py
* Added drop/forward desicions with the learning switch **l2_learning.py:** now the controller doesnt install flow-enteries into the  switch unless there is a forward desicision that this mac adress can forward packets.   
* For simplicity 2 rules where added on switch 1 where any packet coming from ***mac_adress_1*** and ***mac_adress_1*** is forwarded, other than those 2 mac adresses any packets will be droped and no flow-enteries will be installed on the switch
* This is kind of slow; its better to install flow enteries with an action of DROP to the switch rather than checking with the controller first each time
