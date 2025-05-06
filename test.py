f = []

g = {"hund1" : 1}

f.append({"hund1" : 1})

print(f)



[{'problem': 'user/group', 'file content': "New ruels ['-A DOCKER ! -i br-63af15588383 -o br-63af15588383 -j DROP', '-A DOCKER-FORWARD -i docker0 -j ACCEPT', '-A DOCKER-ISOLATION-STAGE-1 -i br-63af15588383 ! -o br-63af15588383 -j DOCKER-ISOLATION-STAGE-2', '-A INPUT -i lo -j ACCEPT', '-A DOCKER-FORWARD -i br-63af15588383 -j ACCEPT', '-A DOCKER ! -i docker0 -o docker0 -j DROP', '-A DOCKER-ISOLATION-STAGE-1 -i docker0 ! -o docker0 -j DOCKER-ISOLATION-STAGE-2'] was found", 'severity': 3}]