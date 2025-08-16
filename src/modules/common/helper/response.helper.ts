export function sendResponse<T>(status: object, message: string, data?: T) {
  const response = {
    ...status,
    message: message,
    data: data,
  };
  return response;
}
