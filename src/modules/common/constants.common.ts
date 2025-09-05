export const message = {
  user: {
    exist: 'This email is already registered.',
    send_code_successfully: 'Verification code sent. Please check your email.',
    verify_successfully: 'Your account has been verified.',
    not_exist: 'Verification information is invalid. Please try again.',
    already_verified: 'Your account is already verified.',
    wrong_verified_code: 'The verification code is incorrect.',
    not_active: 'Your account is not active.',
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
    not_support_change_password:
      'Your account are not supported to change password',
    must_not_same_password:
      'New password must be different from the old password',
    change_password_successfully: 'Change password successfully',
    invalid_credentials: 'The credentials provided are invalid',
    confirm_password_not_match:
      'The new password and its confirmation do not match',
    invalid_payload_token: 'Invalid authentication information',
    get_profile_successfully: 'Get user profile successfully',
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
  google_auth_error: {
    id_token_missing: 'Google did not return id_token',
    invalid_token: 'Invalid Google Token',
    email_not_verified: 'Email is not verified by Google',
  },
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
export const cookieOptions = {
  name: {
    accessToken: 'accessToken',
    refreshToken: 'refreshToken',
    sessionId: 'sessionId',
  },
  maxAge: {
    accessToken: 60 * 60 * 1000, //1hour
    refreshToken: 365 * 24 * 60 * 60 * 1000, //1year
    sessionId: 365 * 24 * 60 * 60 * 1000, //1year
  },
  sameSite: 'strict',
};
