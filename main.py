train_data = {
    'trainNumber': request.form.get('trainNumber', False),
    'time': request.form.get('departure', False),
    'track': request.form.get('tracktype', False),
    'tracktoken': '0'}

temp = insert_timetable(json_data['trains'], train_data)
json_data['trains'] = temp[0]
json_data = trainoccupiestrack(json_data)
data = (["A"] + [temp[1]] + [json_data["trains"][temp[1]]["trainNumber"]] +
        [json_data["trains"][temp[1]]["time"]] +
        [json_data["trains"][temp[1]]["track"]])