package flightapp;

import java.io.*;
import java.sql.*;
import java.util.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * Runs queries against a back-end database
 */
public class Query {
  // DB Connection
  private Connection conn;

  // Password hashing parameter constants
  private static final int HASH_STRENGTH = 65536;
  private static final int KEY_LENGTH = 128;

  // Canned queries
  private static final String CHECK_FLIGHT_CAPACITY = "SELECT capacity FROM Flights WHERE fid = ?";
  private static final String CLEAR_TABLE_SQL = "DELETE FROM Reservations; DELETE FROM Users";
  private static final String GET_PASSWORD_SQL = "SELECT password, salt FROM Users WHERE username = ?";
  private static final String CREATE_CUSTOMER_SQL = "INSERT INTO Users VALUES (?, ?, ?, ?)";
  private static final String DIRECT_FLIGHT_SQL = "SELECT TOP (?) fid FROM Flights " +
   "WHERE origin_city = ? AND dest_city = ? AND day_of_month = ? AND canceled = 0 " +
   "ORDER BY actual_time ASC, fid ASC";
  private static final String INDIRECT_FLIGHT_SQL = "SELECT TOP(?) F1.fid AS 'fid1', F2.fid AS 'fid2'" + 
    "FROM (SELECT * FROM FLIGHTS AS F WHERE F.canceled = 0 AND F.day_of_month = ?) AS F1, (SELECT * FROM FLIGHTS AS F WHERE F.canceled = 0 AND F.day_of_month = ?) AS F2 " +
    "WHERE F1.origin_city = ? AND F2.dest_city = ? " +
    "AND F1.dest_city = F2.origin_city " +
    "GROUP BY F1.fid, F2.fid, F1.origin_city, F1.dest_city, F2.dest_city, F1.actual_time, F2.actual_time " +
    "ORDER BY (F1.actual_time + F2.actual_time) ASC, F1.fid ASC, F2.fid ASC";
  private static final String COUNT_MONTH_SQL = "SELECT COUNT(*) as 'cnt' FROM Reservations as r, Flights as f WHERE " +
    "r.fid1 = f.fid AND f.day_of_month = ? AND username = ?";
  private static final String COUNT_RESERVATIONS = "SELECT COUNT(*) as 'cnt' FROM Reservations WHERE isCancelled = 0";
  private static final String BOOK_SQL = "INSERT INTO Reservations " +
    "(rid, username, isPaid, isCancelled, fid1, fid2) " +
    "VALUES (?, ?, ?, ?, ?, ?)";
  private static final String CHECK_FLIGHT = "SELECT fid1, fid2 FROM Reservations " +
    "WHERE rid = ? AND isPaid = 0 AND isCancelled = 0";
  private static final String SET_BAL = "UPDATE Users SET balance = ? WHERE username = ?";
  private static final String SET_PAID = "UPDATE Reservations SET isPaid = 1 WHERE rid = ?";
  private static final String LIST_RESERVE = "SELECT * FROM Reservations " +
    "WHERE username = ? AND isCancelled = 0";
  private static final String CHECK_PAID  = "SELECT isPaid, isCancelled FROM Reservations WHERE rid = ?";
  private static final String CANCEL_SQL = "UPDATE Reservations SET isCancelled = 1 WHERE rid = ?";
  private static final String CHECK_PRICE = "SELECT fid1, fid2 FROM Reservations WHERE rid = ?";
  private static final String REFUND_SQL = "UPDATE Users SET balance = ?";
  
  // Transaction statements
  private static final String BEGIN_TRANSACTION_SQL = "BEGIN TRANSACTION;";
  private static final String COMMIT_SQL = "COMMIT TRANSACTION";
  private static final String ROLLBACK_SQL = "ROLLBACK TRANSACTION";
  private Statement generalStatement;

  private PreparedStatement checkFlightCapacityStatement;
  private PreparedStatement clearTableStatement;
  private PreparedStatement getPasswordStatement;
  private PreparedStatement createCustomerStatement;
  private PreparedStatement directFlightStatement;
  private PreparedStatement indirectFlightStatement;
  private PreparedStatement countMonthStatement;
  private PreparedStatement countReservationsStatement;
  private PreparedStatement bookStatement;
  private PreparedStatement checkFlightStatement;
  private PreparedStatement setBalStatement;
  private PreparedStatement setPaidStatement;
  private PreparedStatement listReserveStatement;
  private PreparedStatement checkPaidStatement;
  private PreparedStatement cancelStatement;
  private PreparedStatement checkPriceStatement;
  private PreparedStatement refundStatement;

  // For check dangling
  private static final String TRANCOUNT_SQL = "SELECT @@TRANCOUNT AS tran_count";
  private PreparedStatement tranCountStatement;

  // TODO: YOUR CODE HERE
  private String logged_in_user = null;
  private ArrayList<Itinerary> its = new ArrayList<>();
  // make array private arrayItineraries;
  // contains objects having fid1, fid2 (can be null)

  public Query() throws SQLException, IOException {
    this(null, null, null, null);
  }

  protected Query(String serverURL, String dbName, String adminName, String password)
      throws SQLException, IOException {
    conn = serverURL == null ? openConnectionFromDbConn()
        : openConnectionFromCredential(serverURL, dbName, adminName, password);

    prepareStatements();
  }

  /**
   * Return a connecion by using dbconn.properties file
   *
   * @throws SQLException
   * @throws IOException
   */
  public static Connection openConnectionFromDbConn() throws SQLException, IOException {
    // Connect to the database with the provided connection configuration
    Properties configProps = new Properties();
    configProps.load(new FileInputStream("dbconn.properties"));
    String serverURL = configProps.getProperty("hw5.server_url");
    String dbName = configProps.getProperty("hw5.database_name");
    String adminName = configProps.getProperty("hw5.username");
    String password = configProps.getProperty("hw5.password");
    return openConnectionFromCredential(serverURL, dbName, adminName, password);
  }

  /**
   * Return a connecion by using the provided parameter.
   *
   * @param serverURL example: example.database.widows.net
   * @param dbName    database name
   * @param adminName username to login server
   * @param password  password to login server
   *
   * @throws SQLException
   */
  protected static Connection openConnectionFromCredential(String serverURL, String dbName,
      String adminName, String password) throws SQLException {
    String connectionUrl =
        String.format("jdbc:sqlserver://%s:1433;databaseName=%s;user=%s;password=%s", serverURL,
            dbName, adminName, password);
    Connection conn = DriverManager.getConnection(connectionUrl);

    // By default, automatically commit after each statement
    conn.setAutoCommit(true);

    // By default, set the transaction isolation level to serializable
    conn.setTransactionIsolation(Connection.TRANSACTION_SERIALIZABLE);

    return conn;
  }

  /**
   * Get underlying connection
   */
  public Connection getConnection() {
    return conn;
  }

  /**
   * Closes the application-to-database connection
   */
  public void closeConnection() throws SQLException {
    conn.close();
  }

  /**
   * Clear the data in any custom tables created.
   * 
   * WARNING! Do not drop any tables and do not clear the flights table.
   */
  public void clearTables() {
    try {
      clearTableStatement.execute();
    } catch (SQLException e) {
      e.printStackTrace();
    }
  }

  /*
   * prepare all the SQL statements in this method.
   */
  private void prepareStatements() throws SQLException {
    checkFlightCapacityStatement = conn.prepareStatement(CHECK_FLIGHT_CAPACITY);
    tranCountStatement = conn.prepareStatement(TRANCOUNT_SQL);
    clearTableStatement = conn.prepareStatement(CLEAR_TABLE_SQL);
    getPasswordStatement = conn.prepareStatement(GET_PASSWORD_SQL);
    createCustomerStatement = conn.prepareStatement(CREATE_CUSTOMER_SQL);
    directFlightStatement = conn.prepareStatement(DIRECT_FLIGHT_SQL);
    indirectFlightStatement = conn.prepareStatement(INDIRECT_FLIGHT_SQL);
    countMonthStatement = conn.prepareStatement(COUNT_MONTH_SQL);
    countReservationsStatement = conn.prepareStatement(COUNT_RESERVATIONS);
    bookStatement = conn.prepareStatement(BOOK_SQL);
    checkFlightStatement = conn.prepareStatement(CHECK_FLIGHT);
    setBalStatement = conn.prepareStatement(SET_BAL);
    setPaidStatement = conn.prepareStatement(SET_PAID);
    listReserveStatement = conn.prepareStatement(LIST_RESERVE);
    checkPaidStatement = conn.prepareStatement(CHECK_PAID);
    cancelStatement = conn.prepareStatement(CANCEL_SQL);
    checkPriceStatement = conn.prepareStatement(CHECK_PRICE);
    refundStatement = conn.prepareStatement(REFUND_SQL);
    
    // TODO: YOUR CODE HERE
  }

  /**
   * Takes a user's username and password and attempts to log the user in.
   *
   * @param username user's username
   * @param password user's password
   *
   * @return If someone has already logged in, then return "User already logged in\n" For all other
   *         errors, return "Login failed\n". Otherwise, return "Logged in as [username]\n".
   */
  public String transaction_login(String username, String password) {
    int trials = 3;
    while (trials-- > 0) {
      try {
        if (logged_in_user != null) {
          return "User already logged in\n";
        }
        // Getting real password and salt from the username
        conn.setAutoCommit(false);
        getPasswordStatement.clearParameters();
        getPasswordStatement.setString(1, username);
        ResultSet result = getPasswordStatement.executeQuery();
        if (result.next() == false) {
          conn.rollback();
          conn.setAutoCommit(true);
          return "Login failed\n";
        }
        byte[] hashCheck = result.getBytes("password");
        byte[] salt = result.getBytes("salt");
        
        result.close();
        
        // Specify the hash parameters
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, HASH_STRENGTH, KEY_LENGTH);
        
        // Generate the hash
        SecretKeyFactory factory = null;
        byte[] hash = null;
        try {
          factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
          hash = factory.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
          throw new IllegalStateException();
        }
        
        // Checking if the password is correct
        if (Arrays.equals(hash, hashCheck)) {
          logged_in_user = username;
          conn.commit();
          conn.setAutoCommit(true);
          return "Logged in as " + username + "\n";
        } else {
          conn.rollback();
          conn.setAutoCommit(true);
          return "Login failed\n";
        }
      } catch (SQLException e) {
        e.printStackTrace();
      } finally {
        checkDanglingTransaction();
      }
    }
    return "Login failed\n";
  }

  /**
   * Implement the create user function.
   *
   * @param username   new user's username. User names are unique the system.
   * @param password   new user's password.
   * @param initAmount initial amount to deposit into the user's account, should be >= 0 (failure
   *                   otherwise).
   *
   * @return either "Created user {@code username}\n" or "Failed to create user\n" if failed.
   */
  public String transaction_createCustomer(String username, String password, int initAmount) {
    int trials = 3;
    while (trials-- > 0) {
      try {
        // Check if the balance is negative
        if (initAmount < 0) {
          return "Failed to create user\n";
        }
        
        // Generate a random cryptographic salt
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        
        // Specify the hash parameters
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, HASH_STRENGTH, KEY_LENGTH);
        
        // Generate the hash
        SecretKeyFactory factory = null;
        byte[] hash = null;
        try {
          factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
          hash = factory.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
          throw new IllegalStateException();
        }
        createCustomerStatement.clearParameters();
        createCustomerStatement.setString(1, username);
        createCustomerStatement.setBytes(2, hash);
        createCustomerStatement.setBytes(3, salt);
        createCustomerStatement.setInt(4, initAmount);
        
        conn.setAutoCommit(false);
        // Check if the user is already exist
        if (checkUserExist(username)) {
          conn.rollback();
          conn.setAutoCommit(true);
          return "Failed to create user\n";
        }
        createCustomerStatement.execute();
        conn.commit();
        conn.setAutoCommit(true);
        return "Created user " + username +"\n";
      } catch (SQLException e) {
        if (!isDeadLock(e)) {
          e.printStackTrace();
        }
      }
      finally {
        checkDanglingTransaction();
      }
    }
    return "Failed to create user\n";
  }

  /**
   * Implement the search function.
   *
   * Searches for flights from the given origin city to the given destination city, on the given day
   * of the month. If {@code directFlight} is true, it only searches for direct flights, otherwise
   * is searches for direct flights and flights with two "hops." Only searches for up to the number
   * of itineraries given by {@code numberOfItineraries}.
   *
   * The results are sorted based on total flight time.
   *
   * @param originCity
   * @param destinationCity
   * @param directFlight        if true, then only search for direct flights, otherwise include
   *                            indirect flights as well
   * @param dayOfMonth
   * @param numberOfItineraries number of itineraries to return
   *
   * @return If no itineraries were found, return "No flights match your selection\n". If an error
   *         occurs, then return "Failed to search\n".
   *
   *         Otherwise, the sorted itineraries printed in the following format:
   *
   *         Itinerary [itinerary number]: [number of flights] flight(s), [total flight time]
   *         minutes\n [first flight in itinerary]\n ... [last flight in itinerary]\n
   *
   *         Each flight should be printed using the same format as in the {@code Flight} class.
   *         Itinerary numbers in each search should always start from 0 and increase by 1.
   *
   * @see Flight#toString()
   */
  public String transaction_search(String originCity, String destinationCity, boolean directFlight,
    int dayOfMonth, int numberOfItineraries) {
    int trials = 3;
    while (trials-- > 0) {
      try {
        conn.setAutoCommit(false);
        
        its.clear();
        StringBuffer sb = new StringBuffer();
        directFlightStatement.clearParameters();
        directFlightStatement.setInt(1, numberOfItineraries);
        directFlightStatement.setString(2, originCity);
        directFlightStatement.setString(3, destinationCity);
        directFlightStatement.setInt(4, dayOfMonth);
        ResultSet oneHopResults = directFlightStatement.executeQuery();
        while (oneHopResults.next() != false && numberOfItineraries > 0) {
          its.add(new Itinerary(oneHopResults.getInt("fid")));
          numberOfItineraries--;
        }
        oneHopResults.close();
        if (!directFlight && numberOfItineraries > 0) {
          indirectFlightStatement.clearParameters();
          indirectFlightStatement.setInt(1, numberOfItineraries);
          indirectFlightStatement.setInt(2, dayOfMonth);
          indirectFlightStatement.setInt(3, dayOfMonth);
          indirectFlightStatement.setString(4, originCity);
          indirectFlightStatement.setString(5, destinationCity);
          ResultSet twoHopResults = indirectFlightStatement.executeQuery();
          while (twoHopResults.next()) {
            its.add(new Itinerary(twoHopResults.getInt("fid1"), twoHopResults.getInt("fid2")));
          } 
          twoHopResults.close();
        }
        
        Collections.sort(its);
        for (int i = 0; i < its.size(); i++) {
          if (its.get(i).f2 == null) {
            sb.append("Itinerary " + i + ": 1 flight(s), " + its.get(i).f1.time + " minutes\n");
            sb.append(its.get(i).f1.toString());
          } else {
            sb.append("Itinerary " + i + ": 2 flight(s), " + (its.get(i).f1.time + its.get(i).f2.time) + " minutes\n");
            sb.append(its.get(i).f1.toString());
            sb.append(its.get(i).f2.toString());
          } 
        }
        conn.commit();
        conn.setAutoCommit(true);
        
        if(its.isEmpty()){
         return "No flights match your selection\n";
        }
        return sb.toString();
        
      } catch (SQLException e) {
        if (!isDeadLock(e)) {
          e.printStackTrace();
        }
      } finally {
        checkDanglingTransaction();
      }
    }
    return "Failed to search\n";
  }
  
  
  /**
   * Implements the book itinerary function.
   *
   * @param itineraryId ID of the itinerary to book. This must be one that is returned by search in
   *                    the current session.
   *
   * @return If the user is not logged in, then return "Cannot book reservations, not logged in\n".
   *         If the user is trying to book an itinerary with an invalid ID or without having done a
   *         search, then return "No such itinerary {@code itineraryId}\n". If the user already has
   *         a reservation on the same day as the one that they are trying to book now, then return
   *         "You cannot book two flights in the same day\n". For all other errors, return "Booking
   *         failed\n".
   *
   *         And if booking succeeded, return "Booked flight(s), reservation ID: [reservationId]\n"
   *         where reservationId is a unique number in the reservation system that starts from 1 and
   *         increments by 1 each time a successful reservation is made by any user in the system.
   */
  public String transaction_book(int itineraryId) {
    int trials = 3;
    while (trials-- > 0) {
      try {
        if (logged_in_user == null) {
          return "Cannot book reservations, not logged in\n";
        }
        if (itineraryId >= its.size()) {
          return "No such itinerary " + itineraryId + "\n";
        }
        conn.setAutoCommit(false);
        countMonthStatement.clearParameters();
        countMonthStatement.setInt(1, its.get(itineraryId).f1.dayOfMonth);
        countMonthStatement.setString(2, logged_in_user);
        ResultSet rCheckMonth = countMonthStatement.executeQuery();
        rCheckMonth.next();
        if (rCheckMonth.getInt("cnt") > 0) {
          rCheckMonth.close();
          conn.rollback();
          conn.setAutoCommit(true);
          return "You cannot book two flights in the same day\n";
        }
        rCheckMonth.close();
        
        if (its.get(itineraryId).isFull()) {
          conn.rollback();
          conn.setAutoCommit(true);
          return "Booking failed\n";
        }
        ResultSet countResult = countReservationsStatement.executeQuery();
        countResult.next();
        int totalReservations = countResult.getInt("cnt");
        countResult.close();
  
        bookStatement.clearParameters();
        bookStatement.setInt(1, totalReservations + 1);
        bookStatement.setString(2, logged_in_user);
        bookStatement.setInt(3, 0);
        bookStatement.setInt(4, 0);
        bookStatement.setInt(5, its.get(itineraryId).f1.fid);
        if (its.get(itineraryId).f2 == null) {
          bookStatement.setNull(6, java.sql.Types.INTEGER);
        } else {
          bookStatement.setInt(6, its.get(itineraryId).f2.fid);
        }
        bookStatement.execute();
        conn.commit();
        conn.setAutoCommit(true);
        return "Booked flight(s), reservation ID: " + (totalReservations + 1) + "\n";
      } catch(SQLException e) {
        if (!isDeadLock(e)) {
          e.printStackTrace();
        }
      }
      finally {
        checkDanglingTransaction();
      }
    }
    return "Booking failed\n";
  }

  /**
   * Implements the pay function.
   *
   * @param reservationId the reservation to pay for.
   *
   * @return If no user has logged in, then return "Cannot pay, not logged in\n" If the reservation
   *         is not found / not under the logged in user's name, then return "Cannot find unpaid
   *         reservation [reservationId] under user: [username]\n" If the user does not have enough
   *         money in their account, then return "User has only [balance] in account but itinerary
   *         costs [cost]\n" For all other errors, return "Failed to pay for reservation
   *         [reservationId]\n"
   *
   *         If successful, return "Paid reservation: [reservationId] remaining balance:
   *         [balance]\n" where [balance] is the remaining balance in the user's account.
   */
  public String transaction_pay(int reservationId) {
    int trials = 3;
    while (trials-- > 0) {
      try {
        if (logged_in_user == null){
          return "Cannot pay, not logged in\n";
        }
        conn.setAutoCommit(false);
        int bal = checkUserBalance(logged_in_user);
        checkFlightStatement.clearParameters();
        checkFlightStatement.setInt(1, reservationId);
        ResultSet rReserve = checkFlightStatement.executeQuery();
        if (rReserve.next() == false) {
          conn.rollback();
          conn.setAutoCommit(true);
          return "Cannot find unpaid reservation " + reservationId + " under user: " + logged_in_user + "\n";
        }
        Flight f1 = new Flight(rReserve.getInt("fid1"));
        int reservationCost = f1.price;
        int fid2 = rReserve.getInt("fid2");
        if (rReserve.wasNull()) {
          Flight f2 = new Flight(fid2);
          reservationCost += f2.price;
        }
        rReserve.close();
        if (bal < reservationCost) {
          conn.rollback();
          conn.setAutoCommit(true);
          return "User has only " + bal + " in account but itinerary costs " + reservationCost + "\n";
        }
        setBalStatement.clearParameters();
        setBalStatement.setInt(1, bal - reservationCost);
        setBalStatement.setString(2, logged_in_user);
        setBalStatement.executeUpdate();
        setPaidStatement.setInt(1, reservationId);
        setPaidStatement.executeUpdate();
        conn.commit();
        conn.setAutoCommit(true);
        return "Paid reservation: " + reservationId + " remaining balance: " + (bal - reservationCost) + "\n";
      } catch (SQLException e) {
        if (!isDeadLock(e)) {
          e.printStackTrace();
        }
      } finally {
        checkDanglingTransaction();
      }
    }
    return "Failed to pay for reservation " + reservationId + "\n";
  }

  /**
   * Implements the reservations function.
   *
   * @return If no user has logged in, then return "Cannot view reservations, not logged in\n" If
   *         the user has no reservations, then return "No reservations found\n" For all other
   *         errors, return "Failed to retrieve reservations\n"
   *
   *         Otherwise return the reservations in the following format:
   *
   *         Reservation [reservation ID] paid: [true or false]:\n [flight 1 under the
   *         reservation]\n [flight 2 under the reservation]\n Reservation [reservation ID] paid:
   *         [true or false]:\n [flight 1 under the reservation]\n [flight 2 under the
   *         reservation]\n ...
   *
   *         Each flight should be printed using the same format as in the {@code Flight} class.
   *
   * @see Flight#toString()
   */
  public String transaction_reservations() {
    int trials = 3;
    while (trials-- > 0) {
      try {
        if (logged_in_user == null) {
          return "Cannot view reservations, not logged in\n";
        }
        conn.setAutoCommit(false);
        listReserveStatement.clearParameters();
        listReserveStatement.setString(1, logged_in_user);
        ResultSet rList = listReserveStatement.executeQuery();
        if (rList.next() == false) {
          conn.rollback();
          conn.setAutoCommit(true);
          return "No reservations found\n";
        }
        StringBuffer sb = new StringBuffer();
        do {
          int rrid = rList.getInt("rid");
          int risPaid = rList.getInt("isPaid");
          sb.append("Reservation " + rrid + " paid: " + (risPaid == 1? "true": "false") + ":\n");
          Flight f1 = new Flight(rList.getInt("fid1"));
          
          sb.append(f1.toString());
          int fid2 = rList.getInt("fid2");
          if (!rList.wasNull()) {
            Flight f2 = new Flight(fid2);
            sb.append(f2.toString());
          }
        } while(rList.next());
        rList.close();
        conn.commit();
        conn.setAutoCommit(true);
        return sb.toString();
      } catch(SQLException e) {
        if (!isDeadLock(e)) {
          e.printStackTrace(); 
        }
      } finally {
        checkDanglingTransaction();
      }
    }
    return "Failed to retrieve reservations\n";
  }

  /**
   * Implements the cancel operation.
   *
   * @param reservationId the reservation ID to cancel
   *
   * @return If no user has logged in, then return "Cannot cancel reservations, not logged in\n" For
   *         all other errors, return "Failed to cancel reservation [reservationId]\n"
   *
   *         If successful, return "Canceled reservation [reservationId]\n"
   *
   *         Even though a reservation has been canceled, its ID should not be reused by the system.
   */
  public String transaction_cancel(int reservationId) {
    int trials = 3;
    while (trials-- > 0) {
      try {
        if (logged_in_user == null) {
          return "Cannot cancel reservations, not logged in\n";
        }
        
        conn.setAutoCommit(false);
        // Check if it's already cancelled
        checkPaidStatement.clearParameters();
        checkPaidStatement.setInt(1, reservationId);
        ResultSet isPaidResult = checkPaidStatement.executeQuery();
        if (isPaidResult.next() == false) {
          conn.rollback();
          conn.setAutoCommit(true);
          return "Failed to cancel reservation " + reservationId + "\n";
        }
        int isPaid = isPaidResult.getInt("isPaid");
        int isCancelled = isPaidResult.getInt("isCancelled");
        isPaidResult.close();
        
        // Check if it's already paid
        if (isCancelled == 1) {
          conn.rollback();
          conn.setAutoCommit(true);
          return "Failed to cancel reservation " + reservationId + "\n";
        }
        
        cancelStatement.clearParameters();
        cancelStatement.setInt(1, reservationId);
        cancelStatement.executeUpdate();
        
        // Refund if the user has already paid
        if (isPaid == 1) {
          // Find the total cost of the itinerary
          checkPriceStatement.clearParameters();
          checkPriceStatement.setInt(1, reservationId);
          ResultSet rCheckPrice = checkPriceStatement.executeQuery();
          rCheckPrice.next();
          
          Flight f1 = new Flight(rCheckPrice.getInt("fid1"));
          int reservationCost = f1.price;
          int fid2 = rCheckPrice.getInt("fid2");
          if (rCheckPrice.wasNull()) {
            Flight f2 = new Flight(fid2);
            reservationCost += f2.price;
          }
          rCheckPrice.close();
          
          int userBal = checkUserBalance(logged_in_user);
          refundStatement.clearParameters();
          refundStatement.setInt(1, userBal + reservationCost);
          refundStatement.executeUpdate();
        }
        conn.commit();
        conn.setAutoCommit(true);
        return "Canceled reservation " + reservationId + "\n";
      } catch(SQLException e) {
        if (!isDeadLock(e)) {
          e.printStackTrace();
        }
      } finally {
        checkDanglingTransaction();
      }
    }
    return "Failed to cancel reservation " + reservationId + "\n";
  }

  /**
   * Example utility function that uses prepared statements
   */
  private int checkFlightCapacity(int fid) throws SQLException {
    checkFlightCapacityStatement.clearParameters();
    checkFlightCapacityStatement.setInt(1, fid);
    ResultSet results = checkFlightCapacityStatement.executeQuery();
    results.next();
    int capacity = results.getInt("capacity");
    results.close();

    return capacity;
  }
  
  private int checkSeatTaken(int fid) throws SQLException {
    String seatTakenF1 = "SELECT COUNT(*) as 'cnt' FROM Reservations GROUP BY fid1 HAVING fid1 = ?";
    PreparedStatement pSeat1 = conn.prepareStatement(seatTakenF1);
    pSeat1.clearParameters();
    pSeat1.setInt(1, fid);
    ResultSet rSeat1 = pSeat1.executeQuery();
    int seat = 0;
    if (rSeat1.next() != false) {
      seat = rSeat1.getInt("cnt");
    }
    String seatTakenF2 = "SELECT COUNT(*) as 'cnt' FROM Reservations GROUP BY fid2 HAVING fid2 = ?";
    PreparedStatement pSeat2 = conn.prepareStatement(seatTakenF2);
    pSeat2.clearParameters();
    pSeat2.setInt(1, fid);
    ResultSet rSeat2 = pSeat2.executeQuery();
    if (rSeat2.next() != false) {
      seat +=  rSeat2.getInt("cnt");
    }
    // conn.commit();
    return seat;
  }
  
  private int checkUserBalance(String username) throws SQLException {
    String sql = "SELECT balance FROM Users WHERE username = ?";
    PreparedStatement pstmt = conn.prepareStatement(sql);
    pstmt.clearParameters();
    pstmt.setString(1, username);
    ResultSet results = pstmt.executeQuery();
    results.next();
    int bal = results.getInt("balance");
    results.close();
    return bal;
  }
  
  private boolean checkUserExist(String username) throws SQLException {
    String sql = "SELECT * FROM Users WHERE username = ?";
    PreparedStatement pstmt = conn.prepareStatement(sql);
    pstmt.clearParameters();
    pstmt.setString(1, username);
    ResultSet results = pstmt.executeQuery();
    return results.next();

  }

  /**
   * Throw IllegalStateException if transaction not completely complete, rollback.
   * 
   */
  private void checkDanglingTransaction() {
    try {
      try (ResultSet rs = tranCountStatement.executeQuery()) {
        rs.next();
        int count = rs.getInt("tran_count");
        if (count > 0) {
          throw new IllegalStateException(
              "Transaction not fully commit/rollback. Number of transaction in process: " + count);
        }
      } finally {
        conn.setAutoCommit(true);
      }
    } catch (SQLException e) {
      throw new IllegalStateException("Database error", e);
    }
  }

  private static boolean isDeadLock(SQLException ex) {
    return ex.getErrorCode() == 1205;
  }

  /**
   * A class to store flight information.
   */
  class Flight {
    public int fid;
    public int dayOfMonth;
    public String carrierId;
    public int flightNum;
    public String originCity;
    public String destCity;
    public int time;
    public int capacity;
    public int price;
    public Flight(int f) {
      try {
        String findFlights = "SELECT * FROM Flights WHERE fid = ?";
        PreparedStatement pFindFlights = conn.prepareStatement(findFlights);
        pFindFlights.setInt(1, f);
        ResultSet results = pFindFlights.executeQuery();
        if (results.next() != false) {
          fid = f;
          dayOfMonth = results.getInt("day_of_month");
          carrierId = results.getString("carrier_id");
          flightNum = results.getInt("flight_num");
          originCity = results.getString("origin_city");
          destCity = results.getString("dest_city");
          time = results.getInt("actual_time");
          capacity = results.getInt("capacity");
          price = results.getInt("price");
        }
        results.close();
      } catch (SQLException e) {
        if (!isDeadLock(e)) {
          e.printStackTrace();
        }
      }
    }
    @Override
    public String toString() {
      return "ID: " + fid + " Day: " + dayOfMonth + " Carrier: " + carrierId + " Number: "
          + flightNum + " Origin: " + originCity + " Dest: " + destCity + " Duration: " + time
          + " Capacity: " + capacity + " Price: " + price + "\n";
    }
  }
  class Itinerary implements Comparable<Itinerary>{
    public Flight f1;
    public Flight f2;
    public Itinerary(int fid1) {
      f1 = new Flight(fid1);
      f2 = null;
    }
    public Itinerary(int fid1, int fid2) {
      f1 = new Flight(fid1);
      f2 = new Flight(fid2);
    }
    public int getTime() {
      if (f2 != null) {
        return f1.time + f2.time;
      } else {
        return f1.time;
      }
    }
    public int compareTo(Itinerary it) {
      return this.getTime() - it.getTime();
    }
    public boolean isFull() throws SQLException {
      int f1Taken = checkSeatTaken(f1.fid);
      if (f2 != null) {
        int f2Taken = checkSeatTaken(f2.fid);
        return (f1Taken >= f1.capacity) || (f2Taken >= f2.capacity);
      } else {
        return f1Taken >= f1.capacity;
      }
    }
  }
}
