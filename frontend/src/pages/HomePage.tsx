import React from 'react';
import Layout from '../components/Layout.tsx';

const HomePage: React.FC = () => {
  return (
    <Layout>
      <div className="text-center">
        {/* Hero Section */}
        <div className="mb-12">
          <h1 className="text-4xl font-bold text-gray-900 mb-4">
            Welcome to PayrollApp
          </h1>
          <p className="text-xl text-gray-600 mb-8">
            Secure, private payroll processing using encrypted blockchain technology
          </p>
        </div>

        {/* Action Cards */}
        <div className="grid md:grid-cols-2 gap-8 max-w-4xl mx-auto">
          {/* For Employees */}
          <div className="bg-white p-8 rounded-lg shadow-md">
            <h2 className="text-2xl font-semibold text-gray-900 mb-4">
              For Employees
            </h2>
            <p className="text-gray-600 mb-6">
              Register to receive your payroll securely and privately
            </p>
            <button className="bg-green-600 text-white px-6 py-3 rounded-md hover:bg-green-700 transition-colors">
              Employee Registration
            </button>
          </div>

          {/* For Businesses */}
          <div className="bg-white p-8 rounded-lg shadow-md">
            <h2 className="text-2xl font-semibold text-gray-900 mb-4">
              For Businesses
            </h2>
            <p className="text-gray-600 mb-6">
              Process payroll for up to 10 employees at once
            </p>
            <button className="bg-blue-600 text-white px-6 py-3 rounded-md hover:bg-blue-700 transition-colors">
              Business Registration
            </button>
          </div>
        </div>

        {/* Features Section */}
        <div className="mt-16">
          <h3 className="text-2xl font-semibold text-gray-900 mb-8">
            Why Choose PayrollApp?
          </h3>
          <div className="grid md:grid-cols-3 gap-6">
            <div className="text-center">
              <div className="bg-blue-100 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
                <span className="text-2xl">🔒</span>
              </div>
              <h4 className="font-semibold mb-2">Private & Secure</h4>
              <p className="text-gray-600 text-sm">
                Your payroll data is encrypted and private
              </p>
            </div>
            <div className="text-center">
              <div className="bg-green-100 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
                <span className="text-2xl">⚡</span>
              </div>
              <h4 className="font-semibold mb-2">Fast Processing</h4>
              <p className="text-gray-600 text-sm">
                Process up to 10 payments in a single transaction
              </p>
            </div>
            <div className="text-center">
              <div className="bg-purple-100 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
                <span className="text-2xl">🌐</span>
              </div>
              <h4 className="font-semibold mb-2">Blockchain Powered</h4>
              <p className="text-gray-600 text-sm">
                Built on secure blockchain technology
              </p>
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
};

export default HomePage; 