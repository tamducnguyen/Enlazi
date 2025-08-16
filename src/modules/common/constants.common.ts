export const message = {
  user: {
    exist: 'Invalid information. Please check and try again.',
    send_code_successfully:
      'Verification code sent successfully. Please check your email to verify your account.',
    verify_successfully: 'Your account has been verified successfully.',
    not_exist: 'Invalid verification information. Please check and try again.',
    already_verified: 'Your account is already verified.',
    wrong_verified_code: 'The verification code is invalid.',
    verify_require:
      'Your account is not verified. Please verify your account to sign in',
    wrong_password: 'Email or password is invalid. Please type again',
    role_not_exist: 'Invalid information. Please check and try again.',
    sign_out_successfully: 'Sign out successfully',
    sign_in_successfully: 'Sign in successfully',
    refresh_token_successfully: 'Refresh token successfully',
    reset_password_successfully: 'Reset password successfully',
    forbidden: 'Invalid route. Please check and try again.',
    userbanned: 'You are banned! Please try again after 5 minutes',
  },

  auth: {
    ratelimit: {
      too_many_requests: 'You send too many request. Please try again',
    },
    refresh_token: {
      invalid_or_expired: 'This refresh token is invalid or expired',
      missing: 'Invalid information, please try again',
      not_match_cookie_between_body: 'Invalid information, please try again',
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
};
