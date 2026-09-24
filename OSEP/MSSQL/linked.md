
```c#
using System;
using System.Data.SqlClient;

namespace SQL
{
    class Program
    {
        static void Main(string[] args)
        {
            String sqlServer = "dc01.corp1.com";
            String database = "master";

            String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";
            SqlConnection con = new SqlConnection(conString);
           
            try
            {
                con.Open();
                Console.WriteLine("Auth success!");
            }
            catch
            {
                Console.WriteLine("Auth failed");
                Environment.Exit(0);
            }
	        String execCmd = "EXEC sp_linkedservers;";
	
	        SqlCommand command = new SqlCommand(execCmd, con);
	        SqlDataReader reader = command.ExecuteReader();
	
	        while (reader.Read())
	        {
	            Console.WriteLine("Linked SQL server: " + reader[0]);
	        }
	        reader.Close();
	        String queryremote = "select login from openquery(\"dc01\", 'select SYSTEM_USER as login')";
	        SqlCommand command = new SqlCommand(queryremote, con);
	        SqlDataReader reader = command.ExecuteReader();
	        reader.Read();
			Console.WriteLine("Executing as the login " + reader[0] + " on DC01");
			reader.Close();
			
	        con.Close();
        }
    }
}
```

リンクサーバにログインしてsaかどうか見る
```c#
using System;
using System.Data.SqlClient;

namespace SQL
{
    class Program
    {
        static void Main(string[] args)
        {
            String sqlServer = "appsrv01.corp1.com";
            String database = "master";

            String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";
            SqlConnection con = new SqlConnection(conString);
            try
            {
              con.Open();
              Console.WriteLine("Auth success!");
            }
            catch
            {
              Console.WriteLine("Auth failed");
              Environment.Exit(0);
            }
            String querylogin = "SELECT SYSTEM_USER;";
            SqlCommand command = new SqlCommand(querylogin, con);
            SqlDataReader reader = command.ExecuteReader();
            reader.Read();
            Console.WriteLine("Logged in as: " + reader[0]);
            reader.Close();
            
            String querypublicrole = "SELECT IS_SRVROLEMEMBER('public');";
            command = new SqlCommand(querypublicrole, con);
            reader = command.ExecuteReader();
            reader.Read();
            Int32 role = Int32.Parse(reader[0].ToString());
            if(role == 1)
            {
              Console.WriteLine("User is a member of public role");
            }
            else
            {
              Console.WriteLine("User is NOT a member of public role");
            }
            reader.Close();
            
            String querypublicrole = "SELECT IS_SRVROLEMEMBER('sysadmin');";
            command = new SqlCommand(querypublicrole, con);
            reader = command.ExecuteReader();
            reader.Read();
            Int32 role = Int32.Parse(reader[0].ToString());
            if(role == 1)
            {
              Console.WriteLine("User is a member of sysadmin role");
            }
            else
            {
              Console.WriteLine("User is NOT a member of sysadmin role");
            }
            reader.Close();
            
            con.Close();
        }
    }
}
```