import subprocess


class FireWallChecker():
    def __init__(self):
        self.rules = """
-P INPUT DROP
-P FORWARD DROP
-P OUTPUT ACCEPT
-N DOCKER
-N DOCKER-BRIDGE
-N DOCKER-CT
-N DOCKER-FORWARD
-N DOCKER-ISOLATION-STAGE-1
-N DOCKER-ISOLATION-STAGE-2
-N DOCKER-USER
-A INPUT -i lo -j ACCEPT
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p udp -m udp --dport 5353 -j ACCEPT
-A INPUT -m pkttype --pkt-type multicast -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 868 -j ACCEPT
-A INPUT -s 172.0.0.0/8 -p tcp -m tcp --dport 50051 -j ACCEPT
-A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT
-A FORWARD -j DOCKER-USER
-A FORWARD -j DOCKER-FORWARD
-A DOCKER ! -i br-63af15588383 -o br-63af15588383 -j DROP
-A DOCKER ! -i docker0 -o docker0 -j DROP
-A DOCKER-BRIDGE -o br-63af15588383 -j DOCKER
-A DOCKER-BRIDGE -o docker0 -j DOCKER
-A DOCKER-CT -o br-63af15588383 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A DOCKER-CT -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A DOCKER-FORWARD -j DOCKER-CT
-A DOCKER-FORWARD -j DOCKER-ISOLATION-STAGE-1
-A DOCKER-FORWARD -j DOCKER-BRIDGE
-A DOCKER-FORWARD -i br-63af15588383 -j ACCEPT
-A DOCKER-FORWARD -i docker0 -j ACCEPT
-A DOCKER-ISOLATION-STAGE-1 -i br-63af15588383 ! -o br-63af15588383 -j DOCKER-ISOLATION-STAGE-2
-A DOCKER-ISOLATION-STAGE-1 -i docker0 ! -o docker0 -j DOCKER-ISOLATION-STAGE-2
-A DOCKER-ISOLATION-STAGE-2 -o docker0 -j DROP
-A DOCKER-ISOLATION-STAGE-2 -o br-63af15588383 -j DROP
-A DOCKER-USER -j RETURN
"""
    def run_command(self,command):
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            ).stdout.strip()
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to run command: {e.stderr}")
        return result
    
    # a quick metohod to remove a specifik value from a list
    def remove_values_from_list(self, the_list, val):
        return [value for value in the_list if value != val]
    
    def biggest_number(self,num1,num2):
        if num1 > num2:
            return num1
        else:
            return num2

    def check_difrense(self):
        defoulte_rules = self.rules.split("\n")
        defoulte_rules = self.remove_values_from_list(defoulte_rules,"")

        system_rules = self.run_command(['sudo','iptables','-S'])
        system_rules = system_rules.split("\n")
        system_rules = self.remove_values_from_list(system_rules,"")

        if len(system_rules) == len(defoulte_rules):
            print("all good")
        else:
            print(system_rules, "is not",defoulte_rules)
        
        for rule in range(self.biggest_number(len(system_rules),len(defoulte_rules))):
            if system_rules[rule] == defoulte_rules[rule]:
                pass
            elif system_rules[rule] in defoulte_rules:
                ...


if __name__ == "__main__":
    firewalchecker = FireWallChecker()
    firewalchecker.check_difrense()

