/*
 * Stud DTrace provider.
 */

provider stud {
  probe ssl__session__reuse(char* host, int port, long expiry);
  probe ssl__session__new(char* host, int port, long expiry);
  probe ssl__cipher(char* host, int port, char* cipher);
  probe close__side(char* host, int port, int backend);
};
