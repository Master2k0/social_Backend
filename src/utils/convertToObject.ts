const convertToObject = (obj: any) => {
  return JSON.parse(JSON.stringify(obj));
};

export default convertToObject;
