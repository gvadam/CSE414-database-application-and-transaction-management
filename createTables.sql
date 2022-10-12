CREATE TABLE Users(
	username VARCHAR(20) PRIMARY KEY,
	password VARBINARY(20),
	salt VARBINARY(16),
	balance INT
);
CREATE TABLE Reservations(
	rid INT PRIMARY KEY,
	username VARCHAR(20) REFERENCES Users, 
	isPaid INT, -- 1 = paid, 0 = not paid
	isCancelled INT, -- 1 = cancelled, 0 = not cancelled
	fid1 INT NOT NULL,
	fid2 INT
);