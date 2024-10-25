import mysql from 'mysql2/promise';
import apiConfig from './apiConfig';

const dbHost = apiConfig.mysqlHost;
const dbUser = apiConfig.mysqlUser;
const dbPassword = apiConfig.mysqlPassword;
const dbName = apiConfig.mysqlDatabase;

const connectDB = async () => {
  try {
    const connection = await mysql.createConnection({
      host: dbHost || 'localhost',
      user: dbUser || 'root',
      password: dbPassword || '',
      database: dbName || '<%= dbName %>',
    });

    console.log('MySQL connected');
    return connection;
  } catch (error) {
    console.error('Error connecting to MySQL:', error.message);
    process.exit(1);
  }
};

export default connectDB;
