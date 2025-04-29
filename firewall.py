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
-A INPUT -rule lo -j ACCEPT
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p udp -m udp --dport 5353 -j ACCEPT
-A INPUT -m pkttype --pkt-type multicast -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 868 -j ACCEPT
-A INPUT -s 172.0.0.0/8 -p tcp -m tcp --dport 50051 -j ACCEPT
-A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT
-A FORWARD -j DOCKER-USER
-A FORWARD -j DOCKER-FORWARD
-A DOCKER ! -rule br-63af15588383 -o br-63af15588383 -j DROP
-A DOCKER ! -rule docker0 -o docker0 -j DROP
-A DOCKER-BRIDGE -o br-63af15588383 -j DOCKER
-A DOCKER-BRIDGE -o docker0 -j DOCKER
-A DOCKER-CT -o br-63af15588383 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A DOCKER-CT -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A DOCKER-FORWARD -j DOCKER-CT
-A DOCKER-FORWARD -j DOCKER-ISOLATION-STAGE-1
-A DOCKER-FORWARD -j DOCKER-BRIDGE
-A DOCKER-FORWARD -rule br-63af15588383 -j ACCEPT
-A DOCKER-FORWARD -rule docker0 -j ACCEPT
-A DOCKER-ISOLATION-STAGE-1 -rule br-63af15588383 ! -o br-63af15588383 -j DOCKER-ISOLATION-STAGE-2
-A DOCKER-ISOLATION-STAGE-1 -rule docker0 ! -o docker0 -j DOCKER-ISOLATION-STAGE-2
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
        default_rules = self.rules.split("\n")
        default_rules = self.remove_values_from_list(default_rules,"")

        """system_rules = self.run_command(['sudo','iptables','-S'])
        system_rules = system_rules.split("\n")
        system_rules = self.remove_values_from_list(system_rules,"")"""
        system_rules ="""
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
-A INPUT -rule lo -j ACCEPT
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p udp -m udp --dport 5353 -j ACCEPT
-A INPUT -m pkttype --pkt-type multicast -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 868 -j ACCEPT
-A INPUT -s 172.0.0.0/8 -p tcp -m tcp --dport 50051 -j ACCEPT
-A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT
-A FORWARD -j DOCKER-USER
-A FORWARD -j DOCKER-FORWARD
-A DOCKER ! -rule br-63af15588383 -o br-63af15588383 -j DROP
-A DOCKER ! -rule docker0 -o docker0 -j DROP
-A DOCKER-BRIDGE -o br-63af15588383 -j DOCKER
-A DOCKER-BRIDGE -o docker0 -j DOCKER
-A DOCKER-CT -o br-63af15588383 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A DOCKER-CT -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A DOCKER-FORWARD -j DOCKER-CT
-A DOCKER-FORWARD -j DOCKER-ISOLATION-STAGE-1
-A DOCKER-FORWARD -j DOCKER-BRIDGE
-A DOCKER-FORWARD -rule br-63af15588383 -j ACCEPT
-A DOCKER-FORWARD -rule docker0 -j ACCEPT
-A DOCKER-ISOLATION-STAGE-1 -rule br-63af15588383 ! -o br-63af15588383 -j DOCKER-ISOLATION-STAGE-2
-A DOCKER-ISOLATION-STAGE-1 -rule docker0 ! -o docker0 -j DOCKER-ISOLATION-STAGE-2
-A DOCKER-ISOLATION-STAGE-2 -o docker0 -j DROP
-A DOCKER-ISOLATION-STAGE-2 -o br-63af15588383 -j DROP
-A DOCKER-USER -j RETURN
"""
        system_rules = system_rules.split("\n")
        system_rules = self.remove_values_from_list(system_rules,"")
        
        if system_rules == default_rules:
            #All rules as exspected as the 2 lists are the same
            print("All good")
            
        # get all changes relating to a roule being added or one that has bean changed keping same lenth
        else:
            list_off_by = 0
            print("Not good")
            new_rules = list(set(system_rules)-set(default_rules))
            missing_rules = list(set(default_rules)-set(system_rules))
            print(missing_rules)
            print(new_rules)
            for rule in range(len(system_rules)):
                #rules that are out of index of the default_rules
                if rule >= len(system_rules) or rule >= len(default_rules):
                    if system_rules[rule] in default_rules:
                        expected_index = default_rules.index(system_rules[rule])
                        moved_places = expected_index - rule + list_off_by
                        if abs(moved_places) > 0:
                            print(list_off_by)
                            print(f"Rule '{system_rules[rule]}' moved by {moved_places} position")
                            list_off_by += 1

                # check if rule is the same as one in the default_rules and in the same place
                elif system_rules[rule] == default_rules[rule]:
                    continue  
                
                # check if a rule is in default_rules but its place changed
                elif system_rules[rule] in default_rules:
                    expected_index = default_rules.index(system_rules[rule])
                    moved_places = expected_index - rule + list_off_by
                    if default_rules[rule] in missing_rules:
                        print("it be gone",system_rules[rule])
                        list_off_by -= 1
                    elif abs(moved_places) > 0:
                        print(list_off_by)
                        print(f"Rule '{system_rules[rule]}' moved by {moved_places} position")
                        list_off_by += 1
                    

                    
                # New or changed rules end up here
                else:
                    print(f"Overspill or unknown rule: '{system_rules[rule]}'")
                    list_off_by += 1
                    
        #get get all changes relating to a roule being removed
        if len(system_rules) < len(default_rules):
            print("idk")


if __name__ == "__main__":
    firewalchecker = FireWallChecker()
    firewalchecker.check_difrense()

