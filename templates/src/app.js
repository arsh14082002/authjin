import express from 'express';
import cors from 'cors';
import userRoutes from './routes/userRoute.js';
import cookieParser from 'cookie-parser';
import path from "path"
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(cors({ origin: "*" }));
app.use(cookieParser());

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, ",,/public")))

app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.use('/api/user', userRoutes);

export default app;

