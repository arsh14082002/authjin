import express from 'express';
import cors from 'cors';
import userRoutes from '../routes/userRoute.js';

const app = express();
app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.use('/api/user', userRoutes);

export default app;
