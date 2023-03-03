import * as bcrypt from 'bcrypt';

export const hashPassword = async (password: string): Promise<string> => {
  const salt = bcrypt.genSaltSync(10);
  const passHash = await bcrypt.hash(password, salt);
  return passHash;
};

export const comparePassword = async (
  password,
  hashPassword,
): Promise<boolean> => {
  return await bcrypt.compare(password, hashPassword);
};
