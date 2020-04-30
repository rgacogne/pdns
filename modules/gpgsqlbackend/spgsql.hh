/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#pragma once
#include "pdns/namespaces.hh"
#include "pdns/backends/gsql/ssql.hh"

#include <libpq-fe.h>
class SPgSQL : public SSql
{
public:
  SPgSQL(const string &database, const string &host="", const string& port="",
         const string &user="", const string &password="",
         const string &extra_connection_parameters="");

  ~SPgSQL();
  
  SSqlException sPerrorException(const string &reason) override;
  void setLog(bool state) override;
  unique_ptr<SSqlStatement> prepare(const string& query, int nparams) override;
  void execute(const string& query) override;

  void startTransaction() override;
  void rollback() override;
  void commit() override;

  bool isConnectionUsable() override;
  void reconnect() override;

  PGconn* db() { return d_db; }
  bool in_trx() const { return d_in_trx; }

private:
  PGconn* d_db;
  string d_connectstr;
  string d_connectlogstr;
  static bool s_dolog;
  bool d_in_trx;
};

class SPgSQLStatement: public SSqlStatement
{
public:
  SPgSQLStatement(const string& query, bool dolog, int nparams, SPgSQL* db);
  SSqlStatement* bind(const string& name, bool value) override;
  SSqlStatement* bind(const string& name, int value) override;
  SSqlStatement* bind(const string& name, uint32_t value) override;
  SSqlStatement* bind(const string& name, long value) override;
  SSqlStatement* bind(const string& name, unsigned long value) override;
  SSqlStatement* bind(const string& name, long long value) override;
  SSqlStatement* bind(const string& name, unsigned long long value) override;
  SSqlStatement* bind(const string& name, const std::string& value) override;
  using SSqlStatement::bind; // explicitly import bind(const string& name, const DNSName& value)
  SSqlStatement* bind(const string& name, const std::vector<DNSName>& values);
  SSqlStatement* bindNull(const string& name) override;

  SSqlStatement* execute() override;
  bool hasNextRow()override;
  SSqlStatement* nextRow(row_t& row) override;
  SSqlStatement* getResult(result_t& result) override;
  SSqlStatement* reset() override;
  const std::string& getQuery() override
  {
    return d_query;
  }
  void nextResult();

  ~SPgSQLStatement()
  {
    releaseStatement();
  }

private:
  PGconn* d_db() {
    return d_parent->db();
  }

  void releaseStatement() {
    d_prepared = false;
    reset();
  }

  void prepareStatement();
  void allocate();

  string d_query;
  SPgSQL *d_parent;
  PGresult *d_res_set;
  PGresult *d_res;
  bool d_dolog;
  DTime d_dtime; // only used if d_dolog is set
  bool d_prepared;
  int d_nparams;
  int d_paridx;
  char **paramValues;
  int *paramLengths;
  int d_residx;
  int d_resnum;
  int d_fnum;
  int d_cur_set;
};
