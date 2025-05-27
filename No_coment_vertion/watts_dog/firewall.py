import subprocess
import sqlite3


class FireWallChecker():
    def __init__(self, database):
        self.ipv4 = self.run_command(['sudo','iptables','-S'])
        self.ipv6 = self.run_command(['sudo','ip6tables','-S'])
        
        self.database = database
        
        conn = sqlite3.connect(self.database)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT name FROM sqlite_master WHERE type='table' AND name='firewall_rules';
        """)
        table_exists = cursor.fetchone()
        rules_loaded = False

        if table_exists:
            cursor.execute("SELECT version, rules FROM firewall_rules")
            rows = cursor.fetchall()
            rules_dict = {row[0]: row[1] for row in rows}
            if "ip4" in rules_dict and "ip6" in rules_dict:
                self.rules = rules_dict["ip4"]
                self.rules6 = rules_dict["ip6"]
                rules_loaded = True

        if not rules_loaded:
            print("No rules found in the database or both rulesets are not present. Using current system rules.")
            self.rules = self.ipv4
            self.rules6 = self.ipv6
            self.duild_db()

        conn.close()

    def duild_db(self):
        ipv4 = self.run_command(['sudo','iptables','-S'])
        ipv6 = self.run_command(['sudo','ip6tables','-S'])
        
        conn = sqlite3.connect(self.database)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS firewall_rules (
            id      INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            version TEXT    NOT NULL UNIQUE,
            rules   TEXT    NOT NULL
            );
        ''')
        
        cursor.execute(
            "INSERT OR REPLACE INTO firewall_rules (version, rules) VALUES (?, ?)",
            ("ip4", ipv4)
        )
        cursor.execute(
            "INSERT OR REPLACE INTO firewall_rules (version, rules) VALUES (?, ?)",
            ("ip6", ipv6)
        )
        
        conn.commit()
        conn.close()

        
    
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
    
    def remove_values_from_list(self, the_list, val):
        return [value for value in the_list if value != val]
    
    def biggest_number(self,num1,num2):
        if num1 > num2:
            return num1
        else:
            return num2

    def check_difrense(self, default_rules, system_rules):
        
        vialations = []
        
        default_rules = default_rules.split("\n")
        default_rules = self.remove_values_from_list(default_rules,"")
        
        system_rules = system_rules.split("\n")
        system_rules = self.remove_values_from_list(system_rules,"")
        
        if system_rules == default_rules:
            print("All good")
            
        else:
            list_off_by = 0
            print("Not good")
            new_rules = list(set(system_rules)-set(default_rules))
            missing_rules = list(set(default_rules)-set(system_rules))
            print(missing_rules)
            print(new_rules)
            
            if len(missing_rules) > 0:
                vialations.append( {
                    "problem": "firewall",
                    "info": f"Missing ruels {missing_rules} was found",
                    "severity" : 4
                    })
            
            if len(new_rules) > 0:
                vialations.append( {
                    "problem": "firewall",
                    "info": f"New ruels {new_rules} was found",
                    "severity" : 4
                    })
            
            for rule in range(len(system_rules)):
                
                if rule >= len(system_rules) or rule >= len(default_rules):
                    if system_rules[rule] in default_rules:
                        expected_index = default_rules.index(system_rules[rule])
                        moved_places = expected_index - rule + list_off_by
                        if abs(moved_places) > 0:
                            print(list_off_by)
                            print(f"Rule '{system_rules[rule]}' moved by {moved_places} position")
                            vialations.append( {
                                "problem": "firewall",
                                "info": f"Rule '{system_rules[rule]}' moved by {moved_places} position",
                                "severity" : 4
                                })
                            list_off_by += 1


                elif system_rules[rule] == default_rules[rule]:
                    continue  
                
                elif system_rules[rule] in default_rules:
                    expected_index = default_rules.index(system_rules[rule])
                    moved_places = expected_index - rule + list_off_by
                    if default_rules[rule] in missing_rules:
                        print("it be gone",system_rules[rule])
                        
                        vialations.append({
                                "problem": "firewall",
                                "info": f"Rule '{system_rules[rule]}' is missing",
                                "severity" : 4
                                })
                        
                        list_off_by -= 1
                    elif abs(moved_places) > 0:
                        print(list_off_by)
                        print(f"Rule '{system_rules[rule]}' moved by {moved_places} position")
                        
                        vialations.append( {
                                "problem": "firewall",
                                "info": f"Rule '{system_rules[rule]}' moved by {moved_places} position",
                                "severity" : 4
                                })
                        
                        list_off_by += 1
                    

                else:
                    print(f"Overspill or unknown rule: '{system_rules[rule]}'")
                    list_off_by += 1
                    
        if len(system_rules) < len(default_rules):
            print("idk")
        
        return vialations
            
    def check_system_rules(self):
        vialations = []
        
        vialations += self.check_difrense(self.rules, self.ipv4)
        vialations += self.check_difrense(self.rules6, self.ipv6)
        
        return vialations


if __name__ == "__main__":
    firewalchecker = FireWallChecker("database1.db")
    print(firewalchecker.check_system_rules())

