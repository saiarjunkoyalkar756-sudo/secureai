import app from './api/routes';

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`SecureAI Platform API is running on port ${PORT}`);
});
