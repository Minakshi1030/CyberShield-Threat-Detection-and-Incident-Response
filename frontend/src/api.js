import axios from "axios";
const api=axios.create({baseURL:import.meta.env.VITE_API_URL||"http://localhost:5001/api"});
api.interceptors.request.use(c=>{const t=localStorage.getItem("cs_token");if(t)c.headers.Authorization=`Bearer ${t}`;return c;});
api.interceptors.response.use(r=>r,e=>{if(e.response?.status===401){localStorage.removeItem("cs_token");localStorage.removeItem("cs_user");if(location.pathname!=="/login")location.href="/login";}return Promise.reject(e);});
export default api;
