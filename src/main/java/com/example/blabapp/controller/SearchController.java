package com.example.blabapp.controller;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.example.blabapp.utils.Constants;

/**
 * DEMO ONLY: blab search added on the demo/blab-search branch to show Fortify
 * flagging NEW issues on a pull request. It is intentionally vulnerable:
 *   - SQL Injection: the search term is concatenated into the SQL query
 *   - Cross-Site Scripting (Reflected): the search term is echoed back unescaped
 * Do not merge into master.
 */
@Controller
@Scope("request")
public class SearchController {
	private static final Logger logger = LogManager.getLogger("BlabApp:SearchController");

	@RequestMapping(value = "/search", method = RequestMethod.GET, produces = "text/html;charset=UTF-8")
	@ResponseBody
	public String searchBlabs(
			@RequestParam(value = "q", required = false) String q,
			HttpServletRequest httpRequest)
	{
		logger.info("Entering searchBlabs");

		String username = (String) httpRequest.getSession().getAttribute("username");
		if (username == null) {
			return "<p>Please log in to search.</p>";
		}
		if (q == null) {
			q = "";
		}

		StringBuilder html = new StringBuilder();
		// Reflected XSS: user input written to the page without encoding
		html.append("<h3>Results for: ").append(q).append("</h3><ul>");

		Connection connect = null;
		Statement stmt = null;
		try {
			Class.forName("com.mysql.jdbc.Driver");
			connect = DriverManager.getConnection(Constants.create().getJdbcConnectionString());

			// SQL Injection: user input concatenated into the query
			String sql = "SELECT users.blab_name, blabs.content FROM blabs "
					+ "INNER JOIN users ON blabs.blabber = users.username "
					+ "WHERE blabs.content LIKE '%" + q + "%' ORDER BY blabs.timestamp DESC;";
			stmt = connect.createStatement();
			ResultSet results = stmt.executeQuery(sql);

			while (results.next()) {
				html.append("<li><b>").append(results.getString(1)).append("</b>: ")
						.append(results.getString(2)).append("</li>");
			}
		} catch (SQLException | ClassNotFoundException ex) {
			logger.error(ex);
		} finally {
			try {
				if (stmt != null) {
					stmt.close();
				}
				if (connect != null) {
					connect.close();
				}
			} catch (SQLException ex) {
				logger.error(ex);
			}
		}

		html.append("</ul>");
		return html.toString();
	}
}
