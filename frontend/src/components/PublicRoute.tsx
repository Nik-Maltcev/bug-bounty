import { Navigate } from 'react-router-dom';
import { isAuthenticated } from '../services/api';

interface Props {
  children: React.ReactNode;
}

/**
 * PublicRoute - redirects authenticated users to the app dashboard.
 * Used for landing page and login page.
 */
export default function PublicRoute({ children }: Props) {
  if (isAuthenticated()) {
    return <Navigate to="/app" replace />;
  }
  return <>{children}</>;
}
