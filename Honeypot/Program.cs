using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Newtonsoft.Json.Linq;

namespace Honeypot
{
    class Program
    {
       
        
        static void Main()
        {
            /*
            Dictionary<int, List<string>> wordlistId_Wordlist = new Dictionary<int, List<string>>();
            Dictionary<string, int> bot_WordlistId = new Dictionary<string, int>();

            // Iš cowrie logų generuojame JSON kiekvieno boto wordlistą: { "ip": { "user:pass": count } }
            JObject jip_wordlist = AnalyseCowrie(true); // Ar naudoti graitaveikos checkpoint


            // Iš "jip_wordlist" JSON botų wordlistų generuojame du sąrašus:
            //      1.) wordlistId_Wordlist: unikalių wordlistų sąrašas
            //      2.) bot_WordlistId: priskiriame kiekvieną botui unikalaus wordlisto ID
            CreateBotWordlist(jip_wordlist, ref wordlistId_Wordlist, ref bot_WordlistId);


            // Iš "botWordlistId" JSON botų unikalaus wordlisto ID generuojame:
            //          jWordlist_Count: JSON sąrašą kuriame surašyta wordlistų ID pasikartojimų skaičius
            JObject jWordlist_Count = CreateWordlistsCounts(bot_WordlistId);


            // Iš "bot_WordlistId", "wordlistId_Wordlist", "jWordlist_Count" JSON obektų sugeneruojame:
            //          { "wordlistId": {count, wordlist[], ip_list[] } }       
            JObject jWorldBotnetSummary = CreateWorldBotnetsSummary(bot_WordlistId, wordlistId_Wordlist, jWordlist_Count);


            JObject jPopUserpass = new JObject();
            JObject jPopUsername = new JObject();
            JObject jPopPassword = new JObject();
            CreateMostPopularCredentials(jip_wordlist, ref jPopUserpass, ref jPopUsername, ref jPopPassword);
            File.WriteAllText(@"C:\cowrie\PopUserpass.txt", jPopUserpass.ToString());
            File.WriteAllText(@"C:\cowrie\PopUsername.txt", jPopUsername.ToString());
            File.WriteAllText(@"C:\cowrie\PopPassword.txt", jPopPassword.ToString());
            */


            JObject jObject = AnalyseCowrieCommands();
            File.WriteAllText(@"C:\cowrie\Commands.txt", jObject.ToString());
            Console.WriteLine(jObject.ToString());



            Console.WriteLine("done");
            Console.ReadLine();
        }

        
        static JObject AnalyseCowrieCommands()
        {
            JObject commands = new JObject();
            foreach (string path in Directory.GetFiles(@"C:\cowrie\"))
            {
                if(path.Contains("cowrie.json."))
                {
                    string[] jsonFile = File.ReadAllLines(path);
                    foreach (string item in jsonFile)
                    {
                        try
                        {
                            JObject jItem = JObject.Parse(item);
                            if (jItem.ContainsKey("message"))
                            {
                                string message = jItem["message"].ToString();
                                if (message.Split(':')[0].Equals("CMD"))
                                {
                                    string command = message.Substring(message.Split(':')[0].Length + 2);
                                    if (commands.ContainsKey(command))
                                        commands[command] = Convert.ToInt32(commands[command]) + 1;
                                    else
                                        commands.Add(command, 1);
                                }
                            }
                        }
                        catch (Exception) { }
                    }
                }
                Console.WriteLine(path);
            }
            JObjectSortValue(commands);
            return commands;
        }



        static JObject AnalyseCowrie(bool useCheckpoint)
        {
            JObject jip_wordlist = new JObject();

            if (!useCheckpoint)
            {
                foreach (string path in Directory.GetFiles(@"C:\cowrie"))
                {
                    if (path.Contains("cowrie.json."))
                    {
                        loginSummary(path, ref jip_wordlist);
                        Console.WriteLine(path);
                    }
                }
                File.WriteAllText(@"C:\cowrie\ipWordlist.txt", jip_wordlist.ToString());
            }
            else
            {
                if (File.Exists(@"C:\cowrie\ipWordlist.txt"))
                    jip_wordlist = JObject.Parse(File.ReadAllText(@"C:\cowrie\ipWordlist.txt"));
                else
                    throw new Exception(@"Checkpoint Failas neegzistuoja (C:\cowrie\ipWordlist.txt)");
            }
            return jip_wordlist;
        }


        static void loginSummary(string path, ref JObject ipWordlistSummary)
        {
            ipWordlistSummary = new JObject();

            string[] jsonFile = File.ReadAllLines(path);
            foreach (string item in jsonFile)
            {
                try
                {
                    JObject jObject = JObject.Parse(item);
                    if (jObject.ContainsKey("username"))
                    {
                        if (jObject.ContainsKey("password"))
                        {
                            string ip = jObject["src_ip"].ToString();
                            string username = jObject["username"].ToString();
                            string password = jObject["password"].ToString();
                            string pair = username + ":" + password;

                            /*
                            if (ipCountSummary.ContainsKey(ip))
                                ipCountSummary[ip] = Convert.ToInt32(ipCountSummary[ip]) + 1;
                            else
                                ipCountSummary.Add(ip, 1);



                            if (usernameCountSummary.ContainsKey(username))
                                usernameCountSummary[username] = Convert.ToInt32(usernameCountSummary[username]) + 1;
                            else
                                usernameCountSummary.Add(username, 1);



                            if (passwordCountSummary.ContainsKey(password))
                                passwordCountSummary[password] = Convert.ToInt32(passwordCountSummary[password]) + 1;
                            else
                                passwordCountSummary.Add(password, 1);
                                */


                            if (ipWordlistSummary.ContainsKey(ip))
                            {
                                JObject ipObject = (JObject)ipWordlistSummary[ip];
                                if (ipObject.ContainsKey(pair))
                                {
                                    ipObject[pair] = Convert.ToInt32(ipObject[pair]) + 1;
                                }
                                else
                                    ipObject.Add(pair, 1);
                            }
                            else
                            {
                                JObject wordlistObject = new JObject();
                                wordlistObject.Add(pair, 1);
                                ipWordlistSummary.Add(ip, wordlistObject);
                            }

                        }
                    }
                }
                catch (Exception)
                {
                    Console.WriteLine(item);
                }
            }
            JObjectSort(ipWordlistSummary);
        }


        static void CreateBotWordlist(JObject jip_wordlist, ref Dictionary<int, List<string>> wordlistList, ref Dictionary<string, int> jBotWordlistId)
        {
            int wordlistCount = 0;
            foreach (KeyValuePair<string, JToken> bot_wordlist in jip_wordlist)
            {
                string ip = bot_wordlist.Key;
                JObject ipAttackJson = (JObject)bot_wordlist.Value;
                List<string> ipAttackList = ipAttackJson.Properties().Select(p => p.Name).ToList();



                // Check attack list with wordlists
                bool found = false;
                foreach (KeyValuePair<int, List<string>> keyValuePair in wordlistList)
                {
                    int wordlistId = keyValuePair.Key;
                    List<string> wordlist = keyValuePair.Value;
                    if ((ipAttackList.Count == wordlist.Count) && (ipAttackList.Except(wordlist).ToList().Count == 0))
                    {
                        found = true;
                        jBotWordlistId.Add(ip, wordlistId);
                        break;
                    }
                }
                // import new attack list
                if (found == false)
                {
                    wordlistList.Add(wordlistCount, ipAttackList);
                    jBotWordlistId.Add(ip, wordlistCount);
                    wordlistCount++;
                }
            }
        }


        static JObject CreateWordlistsCounts(Dictionary<string, int> botWordlist_Id)
        {
            // ----- Wordlists count summary from BotWordlistId
            JObject jWordlist_Count = new JObject();
            foreach (KeyValuePair<string, int> count in botWordlist_Id)
            {
                string wordlistId = count.Value.ToString();
                if (jWordlist_Count.ContainsKey(wordlistId))
                    jWordlist_Count[wordlistId] = Convert.ToInt32(jWordlist_Count[wordlistId]) + 1;
                else
                    jWordlist_Count.Add(wordlistId, 1);
            }

            // delete dups
            JObject jWordlist_Count_Short = new JObject();
            foreach (KeyValuePair<string, JToken> count in jWordlist_Count)
            {
                if (Convert.ToInt32(count.Value) > 2)
                {
                    jWordlist_Count_Short.Add(count.Key, count.Value);
                }
            }
            JObjectSortValue(jWordlist_Count_Short);
            return jWordlist_Count_Short;
        }


        static JObject CreateWorldBotnetsSummary(Dictionary<string, int> ip_wordlist, 
                                                    Dictionary<int, List<string>> wordlistList,
                                                    JObject jWordlistSummaryShort)
        {
            // WordlistId: { count, wordlist[], ipList[] }
            JObject jWorldBotnetSummary = new JObject();
            foreach (KeyValuePair<string, JToken> wordlistId in jWordlistSummaryShort)
            {
                int id = Convert.ToInt32(wordlistId.Key);
                int count = Convert.ToInt32(wordlistId.Value);

                JObject botnet = new JObject();
                jWorldBotnetSummary.Add(id.ToString(), botnet);
                botnet.Add("count", count);

                JArray wordlist = new JArray(wordlistList[id]);
                botnet.Add("wordlist", wordlist);

                JArray ipList = new JArray();
                botnet.Add("ip", ipList);
                foreach (KeyValuePair<string, int> botWordlist in ip_wordlist)
                    if (Convert.ToInt32(botWordlist.Value) == id)
                        ipList.Add(botWordlist.Key);
            }
            return jWorldBotnetSummary;
        }



        static void CreateMostPopularCredentials(JObject jip_wordlist, 
                                                    ref JObject userpass_count, 
                                                    ref JObject username_count,
                                                    ref JObject password_count)
        {
            foreach (KeyValuePair<string, JToken> ip_wordlist in jip_wordlist)
            {
                JObject bot = (JObject)ip_wordlist.Value;
                foreach (KeyValuePair<string, JToken> pair_count in bot)
                {
                    string userpass = pair_count.Key;
                    string username = pair_count.Key.Split(':')[0];
                    string password = pair_count.Key.Split(':')[1];
                    int count = Convert.ToInt32(pair_count.Value);


                    if (userpass_count.ContainsKey(userpass))
                        userpass_count[userpass] = Convert.ToInt32(userpass_count[userpass]) + count;
                    else
                        userpass_count.Add(userpass, count);


                    if (username_count.ContainsKey(username))
                        username_count[username] = Convert.ToInt32(username_count[username]) + count;
                    else
                        username_count.Add(username, count);


                    if (password_count.ContainsKey(password))
                        password_count[password] = Convert.ToInt32(password_count[password]) + count;
                    else
                        password_count.Add(password, count);

                }
            }
            JObjectSortValue(userpass_count);
            JObjectSortValue(username_count);
            JObjectSortValue(password_count);
        }


        static void JObjectSort(JObject jObj)
        {
            var props = jObj.Properties().ToList();
            foreach (var prop in props)
            {
                prop.Remove();
            }

            foreach (var prop in props.OrderBy(p => p.Name))
            {
                jObj.Add(prop);
                if (prop.Value is JObject)
                    JObjectSort((JObject)prop.Value);
            }
        }


        static void JObjectSortValue(JObject jObj)
        {
            var props = jObj.Properties().ToList();
            foreach (var prop in props)
            {
                prop.Remove();
            }

            foreach (var prop in props.OrderByDescending(p => p.Value))
            {
                jObj.Add(prop);
                if (prop.Value is JObject)
                    JObjectSort((JObject)prop.Value);
            }
        }

    }
}
