import { Navigate, BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import AgentLogViewer from './AgentLogViewer';

function App() {
    return (
      <Router>
        <Routes>
          <Route path="/" element={<Navigate to="/view" />} />
          <Route path="/view/:logName?/:selectedAgentKey?" element={<AgentLogViewer />} />
        </Routes>
      </Router>
    );
  }

export default App;