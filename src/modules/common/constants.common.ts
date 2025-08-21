export const message = {
  user: {
    exist: 'This email is already registered.',
    send_code_successfully: 'Verification code sent. Please check your email.',
    verify_successfully: 'Your account has been verified.',
    not_exist: 'Verification information is invalid. Please try again.',
    already_verified: 'Your account is already verified.',
    wrong_verified_code: 'The verification code is incorrect.',
    verify_require: 'Your account is not active. Please verify first.',
    invalid_email_password: 'Invalid email or password. Please try again.',
    role_not_exist: 'Invalid role information.',
    sign_out_successfully: 'Signed out successfully.',
    sign_in_successfully: 'Signed in successfully.',
    refresh_token_successfully: 'Session refreshed successfully.',
    reset_password_successfully: 'Password has been reset successfully.',
    forbidden: 'Access denied. Invalid route.',
    userbanned:
      'Your account has been temporarily banned. Please try again in 5 minutes.',
    sign_in_with_google_successfully: 'Signed in with Google successfully.',
    wait_before_resend:
      'Please wait 60 seconds before requesting another email.',
  },

  auth: {
    ratelimit: {
      too_many_requests: 'Too many requests. Please try again later.',
    },
    refresh_token: {
      invalid_or_expired: 'The refresh token is invalid or has expired.',
      missing: 'Missing refresh token. Please try again.',
      not_match_cookie_between_body:
        'Refresh token mismatch. Please try again.',
    },
  },
};
export const HttpStatusCodes = {
  OK: { statusCode: 200, error: 'OK' },
  Created: { statusCode: 201, error: 'Created' },
  NoContent: { statusCode: 204, error: 'No Content' },

  BadRequest: { statusCode: 400, error: 'Bad Request' },
  Unauthorized: { statusCode: 401, error: 'Unauthorized' },
  Forbidden: { statusCode: 403, error: 'Forbidden' },
  NotFound: { statusCode: 404, error: 'Not Found' },
  Conflict: { statusCode: 409, error: 'Conflict' },
  UnprocessableEntity: { statusCode: 422, error: 'Unprocessable Entity' },
  TooManyRequests: { statusCode: 429, error: 'Too Many Requests' },
  InternalServerError: { statusCode: 500, error: 'Internal Server Error' },
  ServiceUnavailable: { statusCode: 503, error: 'Service Unavailable' },
};
export const prefix_key_cached = {
  verify_code: 'auth:email-code:',
  forgot_password_code: 'forgotpassword:email-code:',
  number_verified: 'number_verified:email-code:',
  userbanned: 'userbanned:email:',
  signupinfo: 'signupinfo:email:',
  sendmail: 'sendmail:email:',
};
export const ttlCache = 5 * 60 * 1000;
export const ttlCacheEmail = 60 * 1000;
