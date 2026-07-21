using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Web;

public class VulnerableApp
{
    public void SqlInjection(HttpRequest request)
    {
        string id = request.QueryString["id"]; // Source
        string query = "SELECT * FROM users WHERE id = " + id;
        
        using (SqlCommand cmd = new SqlCommand(query)) // Sink
        {
            cmd.ExecuteReader();
        }
    }

    public void CommandInjection(HttpRequest request)
    {
        string cmdInput = request.QueryString["cmd"]; // Source
        Process.Start(cmdInput); // Sink
    }

    public void CrossSiteScripting(HttpRequest request, HttpResponse response)
    {
        string name = request.QueryString["name"]; // Source
        response.Write("Hello " + name); // Sink
    }

    public void PathTraversal(HttpRequest request)
    {
        string filePath = request.QueryString["file"]; // Source
        File.ReadAllText(filePath); // Sink
    }
}
