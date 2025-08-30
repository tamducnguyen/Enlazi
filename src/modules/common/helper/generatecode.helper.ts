/**
 * Generate a numeric verification code.
 * @param length Number of digits in the code (default = 6)
 * @returns string – padded verification code (e.g. "038472")
 */
export function generateVerificationCode(length = 6): string {
  if (length <= 0) {
    throw new Error('Code length must be greater than zero.');
  }

  const max = 10 ** length;
  const random = Math.floor(Math.random() * max);
  return random.toString().padStart(length, '0');
}
