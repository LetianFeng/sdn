# This is the submission from below students:
# Zhen Chen(2665935), Chunyuan Yu(2587628), Letian Feng(2255840)

# Unicast
dpctl add-flow tcp:127.0.0.1:6634 dl_dst=00:00:00:00:00:01,idle_timeout=0,actions=1
dpctl add-flow tcp:127.0.0.1:6634 dl_dst=00:00:00:00:00:02,idle_timeout=0,actions=2
dpctl add-flow tcp:127.0.0.1:6634 dl_dst=00:00:00:00:00:03,idle_timeout=0,actions=3

# Broadcast
dpctl add-flow tcp:127.0.0.1:6634 dl_dst=FF:FF:FF:FF:FF:FF,idle_timeout=0,actions=flood

# Spam Filter
dpctl add-flow tcp:127.0.0.1:6634 tp_dst=25,idle_timeout=0,priority=33000,actions=
