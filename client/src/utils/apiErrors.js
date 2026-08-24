/**
 * Convert FastAPI/Axios error responses into safe, user-readable text.
 *
 * FastAPI may return `detail` as a string or as an array of validation
 * objects. This helper deliberately avoids exposing raw objects or stacks.
 */
export function extractApiError(error, fallbackMessage) {
  const detail = error?.response?.data?.detail;

  if (typeof detail === 'string' && detail.trim()) {
    return detail.trim();
  }

  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) => {
        if (typeof item === 'string') {
          return item.trim();
        }

        if (item && typeof item === 'object') {
          const message =
            typeof item.msg === 'string'
              ? item.msg.trim()
              : typeof item.message === 'string'
                ? item.message.trim()
                : '';

          if (!message) {
            return '';
          }

          const location = Array.isArray(item.loc)
            ? item.loc
                .filter((part) => part !== 'body')
                .map(String)
                .join(' ')
            : '';

          return location ? `${location}: ${message}` : message;
        }

        return '';
      })
      .filter(Boolean);

    if (messages.length > 0) {
      return messages.join('. ');
    }
  }

  return fallbackMessage;
}