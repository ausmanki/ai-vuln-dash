const EnhancedDashboard = ({ dashboardData }) => (
  <div className="dashboard">
    {dashboardData.map((item) => (
      <div key={item.id} className="dashboard-item">
        <h4>{item.title}</h4>
        <p>{item.value}</p>
      </div>
    ))}
  </div>
);

export default EnhancedDashboard;
